{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module OIDC.Web.Handlers
  ( handlers
  ) where


import           Control.Error
import           Control.Lens
import           Control.Monad (unless)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Reader (Reader, ask, asks, local, runReader)
import           Data.Char (isAlpha, isAscii, isLower, isNumber)
import           Data.Either.Validation
import           Data.Semigroup ((<>))
import           Data.Text (Text)
import qualified Data.Text as Text

import           Lucid (HtmlT, renderBST)
import qualified Lucid as H
import           Lucid.Base (commuteHtmlT, makeAttribute, relaxHtmlT)

import           Servant.API ((:<|>) (..))
import           Servant.API.ContentTypes.Html (Html (..))
import           Servant.Server (ServerT)
import           Servant.Server.Auth.Xsrf ()

import           OIDC.Server.UserStore (lookupUserByEmail, lookupUserByUsername)
import           OIDC.Types (Username (..))
import           OIDC.Types.Email (parseEmailAddress, toEmailId)
import           OIDC.Web.Monad (WebM (..), redirectForm)
import           OIDC.Web.Routes (RegForm, RegFormPost, RegFormReq (..), Routes)


handlers :: ServerT Routes WebM
handlers = handleRegistration :<|> handleRegistrationPost

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
    H.script_ [H.src_ "/static/foundation.min.js"] (""::Text)
    H.script_ [H.src_ "/static/foundation.toggler.min.js"] (""::Text)
    H.script_ ("$(document).foundation();" :: Text)

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
      then [H.class_ " is-invalid-input", aria_ "invalid" ""]
      else []

  H.input_ $ attrs <>
    (aria_ "errormessage" (name <> "Error"): invalidAttrs)

form
  :: Text
  -> [e]
  -> Form e a
  -> H.Html a
form csrf es content = do
  unless (null es) $
    H.div_ [ H.class_ "form-error-alert"
           , H.role_ "alert"
           , H.data_ "closable" "" ] $ do
       "There are errors in your form."
       H.button_ [ H.class_ "close-button"
                 , aria_ "label" "Dismiss alert"
                 , H.type_ "button"
                 , H.data_ "close" "" ]
         $ H.span_ [ aria_ "hidden" "true" ] (H.toHtmlRaw ("&times;"::Text))

  H.form_ [H.method_ "post"] $ do
    H.input_ [ H.type_ "hidden"
             , H.value_ csrf
             , H.name_ "csrf_token"
             ]
    runForm es content


handleRegistration ::  Text -> ServerT RegForm WebM
handleRegistration xsrf = render . unloginWrap $ do
  H.h2_ "Registration"
  --TODO: Extract email from header
  regForm [] $ RegFormReq xsrf "" "" "" ""

data RegError
  = RegUsernameTaken
  | RegUsernameIsBad
  | RegEmailTaken
  | RegEmailIsBad
  | RegPasswordTooShort
  | RegPasswordTooSimple
  | RegPasswordNoMatch
  deriving(Eq,Ord,Show)

handleRegistrationPost
  :: Text
  -> ServerT RegFormPost WebM
handleRegistrationPost xsrf arg = do
  unless (xsrf == csrf_token arg)
    $ redirectForm [] "/accounts/registration"

  nameTaken <- runExceptT $ do
    unless (isValidUsername username)
      $ throwE [RegUsernameIsBad]
    ExceptT . fmap (isTaken RegUsernameTaken)
      . lookupUserByUsername
      $ Username username

  emailCheck <- runExceptT $ do
    addr <- case toEmailId <$> parseEmailAddress email of
          Nothing -> throwE [RegEmailIsBad]
          Just ok -> pure ok
    ExceptT $ isTaken RegEmailTaken <$> lookupUserByEmail addr

  let v = nameTaken^.from _Validation
          *> emailCheck ^. from _Validation
          *> passCheck
          *> passEqCheck

  liftIO $ print v

  case v ^. _Validation of
    Right _ -> do
      -- create user and shit
      redirectForm [] "/profile"

    Left errs -> render . unloginWrap $ do
      H.h2_ "Registration"
      regForm errs arg

  where
    RegFormReq{username,email,password,password2} = arg
    passCheck = do
      unless (Text.length password > 8)
        $ _Failure # [RegPasswordTooShort]
      --TODO: password check against DB

    passEqCheck = unless (password == password2)
                  $ _Failure # [RegPasswordNoMatch]

    isTaken e = maybe (Right ()) (const $ Left [e])

    isValidUsername nm = len >= 3 && len <= 24
      && Text.all validLetter (Text.take 1 nm)
      && Text.all validChar  (Text.drop 1 nm)
      where
        len = Text.length nm
        validLetter c = isAscii c && isAlpha c && isLower c
        validChar c = isNumber c || validLetter c || c == '_'

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
             , H.class_ "button"
             , H.value_ "Register" ]
