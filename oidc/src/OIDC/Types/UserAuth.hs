{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module OIDC.Types.UserAuth
  ( UserAuth(..)
  , UserId (..)
  , newUserId
  , userIdFromString
  , Username(..)
  , EmailStatus(..)
  ) where

import           Data.Aeson (FromJSON, ToJSON)
import           Data.Coerce (coerce)
import           Data.Hashable (Hashable)
import           Data.Text (Text)
import           Data.Time (UTCTime)
import           Data.UUID (UUID)
import           Data.UUID as UUID
import           Data.UUID.V4 as UUID
import           Web.HttpApiData (FromHttpApiData, ToHttpApiData)

import           OIDC.Crypto.Password (Password (..))
import           OIDC.Types.Email (EmailAddress)


newtype UserId = UserId { unUserId :: UUID }
    deriving ( Eq, Ord, Show
             , FromHttpApiData, ToHttpApiData
             , ToJSON, FromJSON
             , Hashable )

newUserId :: IO UserId
newUserId = coerce UUID.nextRandom

userIdFromString :: String -> Maybe UserId
userIdFromString = coerce . UUID.fromString

newtype Username = Username { unUserName :: Text }
    deriving ( Eq, Ord, Show
             , FromHttpApiData, ToHttpApiData
             , Hashable )

data EmailStatus
  = EmailUnverified
  | EmailVerified
  deriving(Eq,Ord,Show)

data UserAuth = UserAuth
  { userId            :: UserId
  , userUsername      :: Username
  , userPassword      :: Password
  , userEmail         :: EmailAddress
  , userEmailVerified :: EmailStatus
  , userLockedOut     :: Maybe UTCTime
  , userName          :: Text -- TODO: newtype wrap?
  , userNickname      :: Text
  , userAvatar        :: Maybe Text --TODO: Url it
  , userUpdatedAt     :: UTCTime
  } deriving (Eq, Ord, Show)
