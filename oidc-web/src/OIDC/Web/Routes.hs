{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE TypeOperators         #-}
module OIDC.Web.Routes
  ( Routes
  , RegForm
  , RegFormPost
  , RegFormReq (..)
  , LoginForm
  , LoginFormPost
  , LoginFormReq(..)
  , PasswordChangeFormPost
  , PasswordChangeFormReq(..)
  , UserIdClaim(..)
  ) where

import           Control.Error (note)
import           Control.Lens (preview, view, ( # ), (&), (?~), _Just)
import           Crypto.JWT (StringOrURI, claimIss, claimSub, emptyClaimsSet)
import           Data.Text (Text)
import           GHC.Generics (Generic)
import           Web.FormUrlEncoded

import           Servant.API ((:<|>), (:>), FormUrlEncoded, Get, Post, ReqBody)
import           Servant.API.Auth.Xsrf (XsrfCookie)
import           Servant.API.ContentTypes.Html (Html)
import           Servant.Auth.Server (Auth, Cookie, FromJWT (..), ToJWT (..))
import           Servant.Auth.Server.Remember (Remember)


import           OIDC.Crypto.Jwt (userSub)
import           OIDC.Types (UserId)

type Routes =
       Protected :> XsrfCookie :> RegForm
  :<|> Protected :> XsrfCookie :> RegFormPost
  :<|> Protected :> XsrfCookie :> LoginForm
  :<|> Protected :> XsrfCookie :> LoginFormPost

type Protected = Auth '[Cookie, Remember UserIdClaim] UserIdClaim

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

type PasswordChangeFormPost =
  "accounts"
  :> "password_change"
  :> ReqBody '[FormUrlEncoded] PasswordChangeFormReq
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

data PasswordChangeFormReq = PasswordChangeFormReq
  { csrf_token    :: Text
  , password      :: Text
  , new_password  :: Text
  , new_password2 :: Text
  } deriving(Generic)

instance FromForm PasswordChangeFormReq where

data UserIdClaim = UserIdClaim
  { claimUser   :: UserId
  , claimIssuer :: StringOrURI
  } deriving(Eq, Show)

instance ToJWT UserIdClaim where
  encodeJWT claim =
    emptyClaimsSet
    & claimSub ?~ userSub # claimUser claim
    & claimIss ?~ claimIssuer claim

instance FromJWT UserIdClaim where
  decodeJWT claims =
    note "Can't parse useridclaim" $ UserIdClaim
    <$> preview (claimSub._Just.userSub) claims
    <*> view claimIss claims
