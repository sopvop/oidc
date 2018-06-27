{-# LANGUAGE OverloadedStrings #-}
module OIDC.Web.Handlers
  ( handlers
  ) where

import           Servant.API.ContentTypes.Html (Html (..))
import           Servant.Server (ServerT)

import           OIDC.Web.Monad (WebM (..))
import           OIDC.Web.Routes (RegForm, Routes)

import           Lucid (HtmlT, renderBST)
import qualified Lucid.Html5 as H


handlers :: ServerT Routes WebM
handlers = handleRegistration

unloginWrap
  :: Monad m
  => HtmlT m a
  -> HtmlT m a
unloginWrap body = H.doctypehtml_ $ H.html_ $ do
  H.head_ $ do
    H.link_ [H.rel_ "stylesheet", H.href_ "/static/site.css"]
    mempty
  H.body_ body

render :: Monad m => HtmlT m () -> m Html
render = fmap Html . renderBST

handleRegistration :: ServerT RegForm WebM
handleRegistration = render . unloginWrap $
  H.h2_ "Registration"
