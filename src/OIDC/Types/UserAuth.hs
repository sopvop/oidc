{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module OIDC.Types.UserAuth
  ( UserAuth(..)
  , UserId (..)
  , Username(..)
  ) where

import           Data.Aeson           (FromJSON, ToJSON)
import           Data.Text            (Text)
import           Data.Time            (UTCTime)
import           Data.UUID            (UUID)
import           Web.HttpApiData      (FromHttpApiData, ToHttpApiData)

import           OIDC.Crypto.Password (Password (..))
import           OIDC.Types.Email     (EmailAddress)


newtype UserId = UserId { unUserId :: UUID }
    deriving (Eq, Ord, Show
             , FromHttpApiData, ToHttpApiData
             , ToJSON, FromJSON)


newtype Username = Username { unUserName :: Text }
    deriving (Eq, Ord, Show, FromHttpApiData, ToHttpApiData)

data UserAuth = UserAuth
    { userId        :: UserId
    , userUsername  :: Username
    , userEmail     :: EmailAddress
    , userPassword  :: Password
    , userLockedOut :: Maybe UTCTime
    } deriving (Eq, Ord, Show)


