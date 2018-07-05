module OIDC.Web.Registration
  ( registerNewUser
  , RegError(..)
  ) where

import           Control.Error
import           Control.Lens
import           Control.Monad (unless)
import           Control.Monad.IO.Class (liftIO)
import           Data.Bifunctor (first)
import           Data.Char (isAlpha, isAscii, isLower, isNumber)
import           Data.Either.Validation
import           Data.Text (Text)
import qualified Data.Text as Text
import           OIDC.Crypto.Password
    (CleartextPassword (..), generatePbkdf2Sha256)
import           OIDC.Crypto.RNG (newRNG)
import           OIDC.Server.UserStore
    (HasUserStore, StoreUserError (..), createUser, lookupUserByEmail,
    lookupUserByUsername)
import           OIDC.Types (UserAuth (..), UserId, Username (..))
import qualified OIDC.Types.Email as Email
import           OIDC.Types.UserAuth (newUserId)

data RegError
  = RegUsernameTaken
  | RegUsernameIsBad
  | RegEmailTaken
  | RegEmailIsBad
  | RegPasswordTooShort
  | RegPasswordTooSimple
  | RegPasswordNoMatch
  deriving(Eq,Ord,Show)


registerNewUser
  :: HasUserStore m
  => Username
  -> Text  -- ^ Unchecked email address
  -> CleartextPassword
  -> CleartextPassword
  -> m (Either [RegError] UserId)
registerNewUser username email password password2 = do
  nameTaken <- runExceptT $ do
    unless (isValidUsername username)
      $ throwE [RegUsernameIsBad]
    ExceptT . fmap (isTaken RegUsernameTaken)
      $ lookupUserByUsername username

  emailCheck <- runExceptT $ do
    parsedEmail <- ExceptT . pure . note [RegEmailIsBad]
      $ Email.parseEmailAddress email
    let emailId = Email.toEmailId parsedEmail
    ExceptT $ isTaken RegEmailTaken <$> lookupUserByEmail emailId
    pure parsedEmail

  let
    v :: Validation [RegError] Email.EmailAddress
    v = (nameTaken^.from _Validation)
         *> passEqCheck
         *> passCheck
         *> (emailCheck ^. from _Validation)

  case validationToEither v of
    Left e -> pure $ Left e
    Right emailAddr -> do
      uid <- liftIO newUserId
      rng <- liftIO newRNG
      pass <- liftIO $ generatePbkdf2Sha256 rng password
      let
        auth = UserAuth uid username pass
            (Email.toEmailId emailAddr) emailAddr Nothing
      toResult uid <$> createUser auth

  where
    toResult uid r = case r of
      Left e -> Left (toRegError e)
      Right _ -> Right uid

    toRegError e = case e of
      DuplicateUsername -> [RegUsernameTaken]
      DuplicateEmail -> [RegEmailTaken]

    passCheck = do
      let (CleartextPassword p) = password
      unless (Text.length p >= 8)
        $ _Failure # [RegPasswordTooShort]
      --TODO: password check against DB

    passEqCheck =
        unless (password == password2)
             $ _Failure # [RegPasswordNoMatch]

    isTaken e = maybe (Right ()) (const $ Left [e])

    isValidUsername (Username nm) = len >= 3 && len <= 24
      && Text.all validLetter (Text.take 1 nm)
      && Text.all validChar  (Text.drop 1 nm)
      where
        len = Text.length nm
        validLetter c = isAscii c && isAlpha c && isLower c
        validChar c = isNumber c || validLetter c || c == '_'
