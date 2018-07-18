module OIDC.Types.Email
    ( EmailAddress(..)
    , parseEmailAddress
    , parseEmailAddressBS
    , toText
    ) where

import           Control.Error (hush)
import           Data.ByteString (ByteString)
import           Data.Coerce (coerce)
import           Data.Hashable
import           Data.Text (Text)
import qualified Data.Text.Encoding as Text
import qualified Text.Email.Parser as EV
import qualified Text.Email.Validate as EV

-- | Email address used for mail delivary by user.
newtype EmailAddress = EmailAddress
    { unEmailAddress :: EV.EmailAddress
    } deriving (Eq, Ord, Show)

instance Hashable EmailAddress where
  hashWithSalt s (EmailAddress m) =
    s `hashWithSalt` EV.localPart m
      `hashWithSalt` EV.domainPart m

parseEmailAddressBS :: ByteString -> Maybe EmailAddress
parseEmailAddressBS = coerce . hush . EV.validate

parseEmailAddress :: Text -> Maybe EmailAddress
parseEmailAddress = parseEmailAddressBS . Text.encodeUtf8

toText :: EmailAddress -> Text
toText (EmailAddress addr) = Text.decodeLatin1 $ EV.toByteString addr
