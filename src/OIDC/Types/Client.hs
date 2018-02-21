{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module OIDC.Types.Client
    ( ClientId(..)
--    , ClientAuthMethod(..)
    , ClientAuth(..)
    )
    where

import           Data.Aeson           (FromJSON (..), ToJSON (..))
import           Data.Hashable        (Hashable)
import           Data.Text            (Text)
import           Data.Time            (UTCTime)

import           Web.HttpApiData      (FromHttpApiData, ToHttpApiData)

import           OIDC.Crypto.Password (Password (..))


newtype ClientId = ClientId Text
    deriving ( Eq, Ord, Show
             , FromJSON, ToJSON
             , FromHttpApiData, ToHttpApiData
             , Hashable)
{-
data ClientAuthMethod
  = NoneAuthMethod -- ^ A public client
  | BasicAuthMethod
  | PostDataMethod
  deriving (Eq, Ord, Show)
-}

data ClientAuth = ClientAuth
  { clientId              :: ClientId
  , clientSecret          :: Maybe Password
--  , clientRedirectUris     :: [Url]
  , clientCreatedAt       :: UTCTime
  , clientSecretExpiresAt :: Maybe UTCTime
  } deriving (Eq, Ord, Show)

