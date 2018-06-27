{-# LANGUAGE OverloadedStrings #-}
module OIDC.Web.Handlers
  ( handlers
  ) where

import           Data.Text (Text)

import           Lucid (HtmlT, renderBST)
import qualified Lucid as H
import           Lucid.Base (makeAttribute)

import           Servant.API.ContentTypes.Html (Html (..))
import           Servant.Server (ServerT)

import           OIDC.Web.Monad (WebM (..))
import           OIDC.Web.Routes (RegForm, Routes)


handlers :: ServerT Routes WebM
handlers = handleRegistration

unloginWrap
  :: Monad m
  => HtmlT m ()
  -> HtmlT m ()
unloginWrap body = H.doctypehtml_ $ do
  H.head_ $ do
    H.link_ [H.rel_ "stylesheet", H.href_ "/static/site.css"]
    mempty
  H.body_ $ do
    H.div_ [ H.class_ "top-bar" ] $
      H.div_ [ H.class_ "top-bar-left" ]
      . H.ul_ [ H.class_ "menu" ] $
        H.li_ [ H.class_ "menu-text"] "StageX"

    H.div_ [ H.class_ "navless-content"] $
      H.div_ [H.class_ "grid-x"] $ do
        H.div_ [H.class_ "cell large-4"] mempty -- nav
        H.div_ [H.class_ "cell large-4 medium-6 small-12"] body


render :: Monad m => HtmlT m () -> m Html
render = fmap Html . renderBST

minlength_ :: Text -> H.Attribute
minlength_ = makeAttribute "minlength_"

handleRegistration :: ServerT RegForm WebM
handleRegistration = render . unloginWrap $ do
  H.h2_ "Registration"
  H.form_ [ H.method_ "post" ] $ do
    H.label_ $ do
      "Email address"
      H.input_ [ H.name_ "email"
               , H.type_ "email"
               , H.required_ ""
               ]

    H.label_ $ do
      "Username"
      H.input_ [ H.name_ "username"
               , H.type_ "text"
               , H.autocomplete_ "username"
               , minlength_ "3"
               , H.maxlength_ "32"
               , H.required_ ""
               , H.title_ "Starts with latin letter and is followed by \
                          \letters and numbers without."
               , H.pattern_ "\\s*([a-z]|[A-Z])(\\w|_)+\\s*"
               ]

    H.label_ $ do
      "Password"
      H.input_ [ H.name_ "password"
               , H.type_ "password"
               , H.autocomplete_ "new-password"
               , minlength_ "8"
               , H.maxlength_ "256"
               , H.required_ ""
               ]

    H.label_ $ do
      "Confirm password"
      H.input_ [ H.name_ "password2"
               , H.type_ "password"
               , H.autocomplete_ "new-password"
               , minlength_ "8"
               , H.maxlength_ "256"
               , H.required_ "" ]

    H.input_ [ H.type_ "submit"
             , H.class_ "button"
             , H.value_ "Register" ]
