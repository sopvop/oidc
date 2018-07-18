{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
module OIDC.Web.Handlers
  ( handlers
  ) where


import           Control.Monad (unless)
import           Control.Monad.Reader (Reader, ask, asks, local, runReader)
import           Data.Maybe (catMaybes)
import           Data.Semigroup ((<>))
import           Data.Text (Text)
import           Data.Traversable (for)
import           Lucid (HtmlT, renderBST)
import qualified Lucid as H
import           Lucid.Base (commuteHtmlT, makeAttribute, relaxHtmlT)

import           Servant.API ((:<|>) (..))
import           Servant.API.ContentTypes.Html (Html (..))
import           Servant.Auth.Server (AuthResult (..))
import           Servant.Auth.Server.Remember ()
import           Servant.Auth.Server.Xsrf ()
import           Servant.Server (ServerT)

import           OIDC.Crypto.Password (CleartextPassword (..))
import           OIDC.Types (UserAuth (..), Username (..))
import           OIDC.Web.Monad
    (WebM (..), mkRememberCookieHeader, mkSessionCookieHeader, redirectForm)
import           OIDC.Web.Registration (RegError (..), registerNewUser)
import           OIDC.Web.Routes
    (LoginForm, LoginFormPost, LoginFormReq (..), RegForm, RegFormPost,
    RegFormReq (..), Routes, UserIdClaim)
import           OIDC.Web.SignIn (authenticateUser)

handlers :: ServerT Routes WebM
handlers = handleRegistration :<|> handleRegistrationPost
  :<|> handleLogin :<|> handleLoginPost

unloginWrap
  :: Monad m
  => HtmlT m ()
  -> HtmlT m ()
unloginWrap body = H.doctypehtml_ $ do
  H.head_ $
    H.link_ [H.rel_ "stylesheet", H.href_ "/static/site.css"]

  H.body_ $ do
    H.div_ [ H.class_ "top-bar" ] $
      H.div_ [ H.class_ "top-bar-left" ]
      . H.ul_ [ H.class_ "menu" ] $
        H.li_ [ H.class_ "menu-text"] "StageX"

    H.div_ [ H.class_ "navless-content"] $
      H.div_ [H.class_ "grid-x grid-margin-x"] $
        H.div_ [H.class_ "cell large-4 medium-6 small-12 large-offset-2"] body

    H.script_ [H.src_ "/static/jquery.min.js"] (""::Text)
    H.script_ [H.src_ "/static/site.js"] (""::Text)
    --H.script_ [H.src_ "/static/foundation.min.js"] (""::Text)
    --H.script_ [H.src_ "/static/foundation.toggler.min.js"] (""::Text)
    --H.script_ ("$(document).foundation();" :: Text)
    H.script_ ("site.init();" :: Text)

render :: Monad m => HtmlT m () -> m Html
render = fmap Html . renderBST

minlength_ :: Text -> H.Attribute
minlength_ = makeAttribute "minlength"


aria_ :: Text -> Text -> H.Attribute
aria_ nm = makeAttribute ("aria-" <> nm)

data FormEnv e = FormEnv
  { formErrorList  :: [e]
  , inputHasErrors :: Bool
  , inputId        :: Text
  }

type Form e a = HtmlT (Reader (FormEnv e)) a


calloutAlert
  :: Monad m
  => HtmlT m ()
  -> HtmlT m ()
calloutAlert h =
  H.div_ [ H.class_ "form-error-alert"
         , H.role_ "alert"
         , H.data_ "closable" "" ] $ do
    h
    H.button_ [ H.class_ "close-button"
              , aria_ "label" "Dismiss alert"
              , H.type_ "button"
              , H.data_ "close" "" ]
      $ H.span_ [ aria_ "hidden" "true" ] (H.toHtmlRaw ("&times;"::Text))


runForm :: [e] -> Form e a -> H.Html a
runForm es h = runReader (commuteHtmlT h) env
  where
    env = FormEnv es False ""


formError
  :: Eq e
  => e
  -> Form e ()
  -> Form e ()
formError e msg = formErrors [(e,msg)]

formErrors
  :: Eq e
  => [(e, Form e ())]
  -> Form e ()
formErrors es = do
  env <- ask
  let
    hasError = (`elem` formErrorList env)
    errors = flip concatMap es $ \(e, msg) ->
      [ H.span_ msg | hasError e]
    name = inputId env <> "Error"
  unless (null errors)
    $ H.p_ [H.id_ name, H.class_ "form-error is-visible"]
      $ sequence_ errors

labeledInput
  :: Eq e
  => Text
  -> [e]
  -> Form e a
  -> Form e a
labeledInput nm es h = do
  hasErrors <- asks $ (\errs -> any (`elem` errs) es) . formErrorList
  H.label_ (labAttrs hasErrors) $
    local (\e -> e { inputHasErrors = hasErrors, inputId=nm }) h
  where
    labAttrs hasErrs  =
      [H.id_ $ nm <> "Label"] <> [ H.class_ "is-invalid-label" | hasErrs]

formInput
  :: [H.Attribute]
  -> Form e ()
formInput attrs = do
  env <- ask
  let
    hasErrors = inputHasErrors env
    name = inputId env
    invalidAttrs =
      if hasErrors
      then [H.id_ name, H.class_ " is-invalid-input", aria_ "invalid" ""]
      else []

  H.input_ $ attrs <>
    (aria_ "errormessage" (name <> "Error"): invalidAttrs)

form
  :: Text
  -> [e]
  -> Form e a
  -> H.Html a
form csrf es content =
  H.form_ [H.method_ "post"] $ do
    H.input_ [ H.type_ "hidden"
             , H.value_ csrf
             , H.name_ "csrf_token"
             ]
    runForm es content


handleRegistration
  :: AuthResult UserIdClaim
  -> Text
  -> ServerT RegForm WebM
handleRegistration auth xsrf = render . unloginWrap $ do
  H.h2_ "Registration"
  --TODO: Extract email from header
  regForm [] $ RegFormReq xsrf "" "" "" ""


handleRegistrationPost
  :: AuthResult UserIdClaim
  -> Text
  -> ServerT RegFormPost WebM
handleRegistrationPost auth xsrf arg = do
  unless (xsrf == csrf_token)
    $ redirectForm [] "/accounts/registration"

  res <- registerNewUser (Username username)
    email (CleartextPassword password) (CleartextPassword password2)

  case res of
    Right _ -> redirectForm [] "/profile"

    Left errs -> render . unloginWrap $ do
      H.h2_ "Registration"
      regForm errs arg

  where
    RegFormReq
      { csrf_token
      , username
      , email
      , password
      , password2 } = arg

regForm
  :: Monad m
  => [RegError]
  -> RegFormReq
  -> HtmlT m ()
regForm errs req = relaxHtmlT $ do
  let RegFormReq{..} = req
  form csrf_token errs $ do
    labeledInput "email" [RegEmailIsBad, RegEmailTaken] $ do
      "Email address"
      formInput [ H.name_ "email"
                , H.type_ "email"
                , H.required_ ""
                , H.value_ email
                ]
      formErrors [(RegEmailIsBad, "Not a valid email format")
                 ,(RegEmailTaken, "Email already taken")]

    labeledInput "username" [RegUsernameTaken, RegUsernameIsBad] $ do
      "Username"
      formInput [ H.name_ "username"
                , H.type_ "text"
                , H.autocomplete_ "username"
                , minlength_ "3"
                , H.maxlength_ "32"
                , H.required_ ""
                , H.title_ "Starts with latin letter and is followed by\
                           \ letters and numbers without spaces."
                , H.pattern_ "\\s*([a-z]|[A-Z])(\\w|_)+\\s*"
                , H.value_ username
                ]
      formErrors [(RegUsernameTaken,"Please choose another username")
                 ,(RegUsernameIsBad,
          "Username should be at least 3 charactes long and contain \
          \only lowercase letters, numbers or underscores. \
          \Must start with a letter.")]


    labeledInput "password" [RegPasswordTooShort, RegPasswordTooSimple] $ do
      "Password"
      formInput [ H.name_ "password"
                , H.type_ "password"
                , H.autocomplete_ "new-password"
                , minlength_ "8"
                , H.maxlength_ "256"
                , H.required_ ""
                , H.title_ "Choose a strong password with a mix of letters of\
                           \ different capitalization, numbers and symbols. Best\
                           \ passwords are random and are stored kept in\
                           \ password manager."
                ]
      formErrors
       [(RegPasswordTooShort
        ,"Please choose password at least 8 characters long")
       ,(RegPasswordTooSimple
        ,"Please choose a more complex password")
       ]


    labeledInput "password2" [RegPasswordNoMatch] $ do
      "Confirm password"
      formInput [ H.name_ "password2"
               , H.type_ "password"
               , H.autocomplete_ "new-password"
               , minlength_ "8"
               , H.maxlength_ "256"
               , H.required_ ""
               , H.title_ "Re-type your password"
               ]
      formError RegPasswordNoMatch
        "Passwords should match"

    H.input_ [ H.type_ "submit"
             , H.class_ "button expanded"
             , H.value_ "Register" ]




handleLogin
  :: AuthResult UserIdClaim
  -> Text
  -> ServerT LoginForm WebM
handleLogin auth xsrf = render . unloginWrap $ do
  H.h2_ "Sign-in"
  --TODO: Extract email from header
  loginForm [] $ LoginFormReq xsrf "" "" Nothing

data LoginError
  = LoginUserNotFount
  | LoginBadPassword
  deriving(Eq,Ord,Show)

handleLoginPost
  :: AuthResult UserIdClaim
  -> Text
  -> ServerT LoginFormPost WebM
handleLoginPost sessionAuth xsrf arg = do
  unless (xsrf == csrf_token)
    $ redirectForm [] "/accounts/login"

  auth <- authenticateUser
    username
    (CleartextPassword password)
    (remember == Just "on")

  case auth of
    Just (usr, rememberToken) -> do

      sessionCookie <- mkSessionCookieHeader usr

      rememberCookie <- for rememberToken $
        mkRememberCookieHeader (userId usr)
      let
        headers = catMaybes [ sessionCookie
                            , rememberCookie ]

      redirectForm headers "/profile" --TODO: cookies
    Nothing ->  render . unloginWrap $ do
      H.h2_ "Sign-in"
      loginForm [()] arg

  where
    LoginFormReq
      { csrf_token
      , username
      , password
      , remember } = arg

loginForm
  :: Monad m
  => [()]
  -> LoginFormReq
  -> HtmlT m ()
loginForm errs req = relaxHtmlT $ do
  let LoginFormReq{..} = req
  form csrf_token errs $ do
    labeledInput "username" [()] $ do
      "Username or email"
      formInput [ H.name_ "username"
                , H.type_ "text"
                , H.autocomplete_ "username"
                , minlength_ "3"
                , H.maxlength_ "128"
                , H.required_ ""
                , H.title_ "Your username or email"
                , H.value_ username
                ]

    labeledInput "password" [()] $ do
      "Password"
      formInput [ H.name_ "password"
                , H.type_ "password"
                , H.autocomplete_ "current-password"
                , minlength_ "8"
                , H.maxlength_ "256"
                , H.required_ ""
                , H.title_ "Your password"
                ]

    labeledInput "remember" [] $ do

      formInput $ [ H.name_ "remember"
                , H.type_ "checkbox"
                , H.value_ "on"
                ] <>  [ H.checked_ | remember == Just "on" ]

      H.label_ [H.for_ "remember"] "Remember me"

    H.input_ [ H.type_ "submit"
             , H.class_ "button expanded"
             , H.value_ "Sign-in" ]


handleProfile auth = do
  render . unloginWrap $ do
    H.h2_ "Sign-in"
