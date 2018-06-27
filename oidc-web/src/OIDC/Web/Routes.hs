{-# LANGUAGE DataKinds     #-}
{-# LANGUAGE TypeOperators #-}
module OIDC.Web.Routes
  ( Routes
  , RegForm
  ) where


import           Servant.API ((:<|>), (:>), Get, Post)

import           Servant.API.ContentTypes.Html (Html)

type Routes = RegForm

type RegForm =
  "accounts"
  :> "registration"
  :> Get '[Html] Html
