{-# LANGUAGE OverloadedStrings #-}
module OIDC.Types
    ( UserAuth(..)
    , UserId
    , Username
    , Password(..)
    , CleartextPassword(..)
    , EmailAddress

    , RememberToken

    , GrantType (..)
    , TokenResponse(..)
    , TokenRequestError(..)
    , PasswordGrantRequest(..)

    ) where

import           Data.Text            (Text)
import           Data.Time            (UTCTime)

import           Web.FormUrlEncoded   (FromForm (..))
import qualified Web.FormUrlEncoded   as Form

import           OIDC.Crypto.Password (CleartextPassword (..), Password (..))

data GrantType
    = AuthorizationCodeGrant
    | ClientCredentialsGrant
    | PasswordGrant
    | RefreshTokenGrant
    | CustomGrant Text
      deriving (Eq, Ord, Show)

data ResponseType
    = CodeRespone
    | TokenResponse
    | CustomResponse Text
      deriving (Eq, Ord, Show)

type Scope = Text
type RedirectUri = Text
type Username = Text
type AccessToken = Text
type RefreshToken = Text
type AuthorizationCode = Text
type ClientId = Text
type ClientSecret = Text
type Url = Text
type State = Text
type Seconds = Int
type TokenType = Text
type UserId = Text
type EmailAddress = Text
type RememberToken = Text

data UserAuth = UserAuth
    { userId        :: UserId
    , userUsername  :: Username
    , userEmail     :: EmailAddress
    , userPassword  :: Password
    , userLockedOut :: Maybe UTCTime
    } deriving (Eq, Ord, Show)


-- | Either @token@ or @code@ request to authorization endpoint.
data AuthRequest = AuthRequest
    { arClientId    :: ClientId
    , arRedirectUri :: Maybe RedirectUri
    , arScope       :: Maybe Scope
    , arState       :: Maybe State
    } deriving (Eq, Show)

-- |  Response to @code@ type authorization request from
-- authorization endpoint
data AuthCodeResponse = AuthCodeResponse
    { areCode  :: AuthorizationCode
    , areState :: State
    } deriving (Eq, Show)

-- | @authorization_code@ request to token endpoint.
data AccessTokenRequest = AccessTokenRequest
    { atrCode        :: AuthorizationCode
    , atrRedirectUri :: Maybe RedirectUri
    , atrClientId    :: Maybe ClientId
    } deriving(Eq, Show)


data PasswordGrantRequest = PasswordGrantRequest
    { pgrUsername :: Username
    , pgrPassword :: CleartextPassword
    , pgrScope    :: Maybe Scope
    } deriving (Eq, Show)

instance FromForm PasswordGrantRequest where
  fromForm f =
    PasswordGrantRequest
    <$> Form.parseUnique "username" f
    <*> Form.parseUnique "password" f
    <*> Form.parseMaybe "scope" f

data TokenResponse = TokenRespose
    { respAccessToken  :: AccessToken
    , respTokenType    :: TokenType
    , respExpiresIn    :: Maybe Seconds
    , respRefreshToken :: Maybe RefreshToken
    , respScope        :: Maybe Scope
    } deriving (Eq, Show)


data OIDCError = OIDCError
    { oidcError            :: Text
    , oidcErrorDescription :: Maybe Text
    , oidcErrorUri         :: Maybe Url
    } deriving (Eq, Show)

data AuthRequestErrors
    = AuthInvalidRequest
    | AuthUnauthorizedClient
    | AuthAccessDenied
    | AuthUnsupportedResponseType
    | AuthInvalidScope
    | AuthServerError
    | AuthTemporarilyUnavailable
      deriving (Eq, Ord, Show)

data TokenRequestError
    = TokenInvalidRequest
    | TokenInvalidClient
    | TokenInvalidGrant
    | TokenUnauthorizedClient
    | TokenUnsupportedGrantType
    | TokenInvalidScope
      deriving (Eq, Ord, Show)
