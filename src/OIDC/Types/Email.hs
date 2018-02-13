{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE OverloadedStrings #-}
module OIDC.Types.Email
    ( EmailId(..)
    , EmailAddress(..)
    , toEmailId
    , parseEmailAddress
    , parseEmailAddressBS
    ) where

import           Control.Error       (hush)
import           Data.ByteString     (ByteString)
import qualified Data.ByteString     as BS
import           Data.Coerce         (coerce)
import           Data.Semigroup      ((<>))
import           Data.Text           (Text)
import qualified Data.Text.Encoding  as Text
import           Data.Word           (Word8)
import qualified Text.Email.Parser   as EV
import qualified Text.Email.Validate as EV

-- | Email address with dots @.@ and characters after @+@ sign
-- in local part stripped. Used as unique key for email addresses.
newtype EmailId = EmailId
    { unEmailId :: Text
    } deriving (Eq, Ord, Show)

-- | Email address used for mail delivary by user.
newtype EmailAddress = EmailAddress
    { unEmailAddress :: EV.EmailAddress
    } deriving (Eq, Ord, Show)

parseEmailAddressBS :: ByteString -> Maybe EmailAddress
parseEmailAddressBS = coerce . hush . EV.validate

parseEmailAddress :: Text -> Maybe EmailAddress
parseEmailAddress = parseEmailAddressBS . Text.encodeUtf8

toEmailId :: EmailAddress -> EmailId
toEmailId (EmailAddress addr) = EmailId result
  where
    !result = localPart <> "@" <> domainPart
    domainPart = Text.decodeLatin1 $ EV.domainPart addr
    localPart = Text.decodeLatin1 . BS.filter (/= dot)
                . BS.takeWhile (/= plus) $ EV.localPart addr
    plus = 43 :: Word8
    dot = 46 :: Word8
