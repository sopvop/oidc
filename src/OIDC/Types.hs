{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TemplateHaskell            #-}
module OIDC.Types
    ( UserAuth(..)
    , UserId(..)
    , Username(..)
    , Password(..)
    , CleartextPassword(..)
    , EmailId(..)
    , EmailAddress (..)

    , ClientId(..)
    , ClientAuth(..)

    , Base64Url(..)

    , AccessToken(..)
    , RememberToken

    , GrantType (..)
    , AccessTokenResponse(..)
    , TokenRequestError(..)
    , PasswordGrantRequest(..)

    ) where

import           Crypto.JWT              (SignedJWT)
import           Data.Aeson              (FromJSON (..), ToJSON (..), withText)
import           Data.Aeson.Encoding     (unsafeToEncoding)
import           Data.Aeson.TH
    (Options (..), defaultOptions, deriveJSON)
import           Data.Aeson.Types        (camelTo2)
import           Data.ByteString         (ByteString)
import qualified Data.ByteString.Builder as BL
import qualified Data.ByteString.Lazy    as BL
import           Data.Semigroup          ((<>))
import           Data.Text               (Text)
import qualified Data.Text.Encoding      as Text
import           Data.Time               (UTCTime)
import           Web.FormUrlEncoded      (FromForm (..))
import qualified Web.FormUrlEncoded      as Form
import           Web.HttpApiData         (FromHttpApiData, ToHttpApiData)

import           OIDC.Crypto.Password    (CleartextPassword (..), Password (..))
import           OIDC.Types.Client       (ClientAuth (..), ClientId (..))
import           OIDC.Types.Email        (EmailAddress (..), EmailId (..))
import           OIDC.Types.UserAuth
    (UserAuth (..), UserId (..), Username (..))

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
type RefreshToken = Text
type AuthorizationCode = Text
type ClientSecret = Text
type Url = Text
type State = Text
type Seconds = Int
type TokenType = Text
type RememberToken = Text


-- | unpadded url-safe base64 encoded @ByteString@
newtype Base64Url = Base64Url
  { unBase64Url :: ByteString }
  deriving (Eq, Ord, Show)

instance ToJSON Base64Url where
  toJSON (Base64Url t) = toJSON (Text.decodeLatin1 t)
  toEncoding (Base64Url t) = unsafeToEncoding $
     BL.char7 '"' <> BL.byteString t <> BL.char7 '"'

instance FromJSON Base64Url where
  parseJSON = withText "access_token" $ \t ->
      pure $ Base64Url $ Text.encodeUtf8 t

newtype AccessToken = AccessToken
  { unAccessToken :: Base64Url
  } deriving (Eq, Ord, Show, FromJSON, ToJSON)


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
    { pgrUsername :: !Username
    , pgrPassword :: !CleartextPassword
    , pgrScope    :: !(Maybe Scope)
    } deriving (Eq, Show)

instance FromForm PasswordGrantRequest where
  fromForm f =
    PasswordGrantRequest
    <$> Form.parseUnique "username" f
    <*> Form.parseUnique "password" f
    <*> Form.parseMaybe "scope" f

data AccessTokenResponse = AccessTokenResponse
    { respAccessToken  :: !AccessToken
    , respTokenType    :: !TokenType
    , respExpiresIn    :: !(Maybe Seconds)
    , respRefreshToken :: !(Maybe RefreshToken)
    , respScope        :: !(Maybe Scope)
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
    | TokenServerError
    | TokenTemporarilyUnavailable
      deriving (Eq, Ord, Show)


$(let opts n = defaultOptions
       { fieldLabelModifier = camelTo2 '_' . drop n }
  in deriveJSON (opts 4)  ''AccessTokenResponse)
