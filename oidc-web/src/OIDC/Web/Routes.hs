{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE TypeOperators         #-}
module OIDC.Web.Routes
  ( Routes
  , RegForm
  , RegFormPost
  , RegFormReq (..)
  , LoginForm
  , LoginFormPost
  , LoginFormReq(..)
  ) where

import           Data.Text (Text)
import           GHC.Generics (Generic)
import           Web.FormUrlEncoded

import           Servant.API ((:<|>), (:>), FormUrlEncoded, Get, Post, ReqBody)
import           Servant.API.Auth.Xsrf (XsrfCookie)
import           Servant.API.ContentTypes.Html (Html)

type Routes = XsrfCookie :> RegForm
              :<|> XsrfCookie :> RegFormPost
              :<|> XsrfCookie :> LoginForm
              :<|> XsrfCookie :> LoginFormPost

type RegForm =
  "accounts"
  :> "registration"
  :> Get '[Html] Html

type RegFormPost =
  "accounts"
  :> "registration"
  :> ReqBody '[FormUrlEncoded] RegFormReq
  :> Post '[Html] Html

type LoginForm =
  "accounts"
  :> "login"
  :> Get '[Html] Html

type LoginFormPost =
  "accounts"
  :> "login"
  :> ReqBody '[FormUrlEncoded] LoginFormReq
  :> Post '[Html] Html



data RegFormReq = RegFormReq
  { csrf_token :: Text
  , username   :: Text
  , email      :: Text
  , password   :: Text
  , password2  :: Text
  } deriving(Generic)

instance FromForm RegFormReq where

data LoginFormReq = LoginFormReq
  { csrf_token :: Text
  , username   :: Text
  , password   :: Text
  , remember   :: Maybe Text
  } deriving(Generic)

instance FromForm LoginFormReq where

