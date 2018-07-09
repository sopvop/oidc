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
  , UserIdClaim(..)
  ) where

import           Control.Lens (( # ), (&), (?~))
import           Crypto.JWT (StringOrURI, claimIss, claimSub, emptyClaimsSet)
import           Data.Text (Text)
import           GHC.Generics (Generic)
import           Web.FormUrlEncoded

import           Servant.API ((:<|>), (:>), FormUrlEncoded, Get, Post, ReqBody)
import           Servant.API.Auth.Xsrf (XsrfCookie)
import           Servant.API.ContentTypes.Html (Html)
import           Servant.Auth.Server (ToJWT (..))


import           OIDC.Crypto.Jwt (userSub)
import           OIDC.Types (UserId)

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

data UserIdClaim = UserIdClaim
  { claimUser   :: UserId
  , claimIssuer :: StringOrURI
  }

instance ToJWT UserIdClaim where
  encodeJWT claim =
    emptyClaimsSet
    & claimSub ?~ userSub # claimUser claim
    & claimIss ?~ claimIssuer claim
