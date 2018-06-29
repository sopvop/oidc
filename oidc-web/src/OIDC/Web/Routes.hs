{-# LANGUAGE DataKinds     #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TypeOperators #-}
module OIDC.Web.Routes
  ( Routes
  , RegForm
  , RegFormPost
  , RegFormReq (..)
  ) where

import           Data.Text (Text)
import           GHC.Generics (Generic)
import           Web.FormUrlEncoded

import           Servant.API ((:<|>), (:>), FormUrlEncoded, Get, Post, ReqBody)
import           Servant.API.Auth.Xsrf (XsrfCookie)
import           Servant.API.ContentTypes.Html (Html)

type Routes = XsrfCookie :> RegForm
              :<|> XsrfCookie :> RegFormPost

type RegForm =
  "accounts"
  :> "registration"
  :> Get '[Html] Html

type RegFormPost =
  "accounts"
  :> "registration"
  :> ReqBody '[FormUrlEncoded] RegFormReq
  :> Post '[Html] Html



data RegFormReq = RegFormReq
  { csrf_token :: Text
  , username   :: Text
  , email      :: Text
  , password   :: Text
  , password2  :: Text
  } deriving(Generic)

instance FromForm RegFormReq where

