module OIDC.Web.SignIn
  ( authenticateUser
  ) where

import           Control.Error (MaybeT (..), nothing, runMaybeT)
import           Control.Monad (unless)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans (lift)
import           Data.Text (Text)
import           Data.Time (getCurrentTime)
import           OIDC.Crypto.Password (CleartextPassword (..), verifyPassword)
import           OIDC.Server.UserStore
    (HasUserStore, RememberToken, lookupUserByEmail, lookupUserByUsername,
    storeRememberToken)
import           OIDC.Types (UserAuth (..), Username (..))
import qualified OIDC.Types.Email as Email
import           OIDC.Web.Monad (HasWebCrypto, newRememberToken)

data SingInError
  = SignInUserNotFound
  | SignInBadPassword
  deriving (Eq,Ord,Show)

authenticateUser
  :: HasUserStore m
  => HasWebCrypto m
  => Text
  -> CleartextPassword
  -> Bool
  -> m (Maybe (UserAuth, Maybe RememberToken))
authenticateUser usernameOrEmail password remember = runMaybeT $ do
  user <- MaybeT $ case Email.parseEmailAddress usernameOrEmail of
      Just addr -> lookupUserByEmail addr
      Nothing -> lookupUserByUsername (Username usernameOrEmail)

  unless (verifyPassword password $ userPassword user)
    nothing

  tok <- if remember
    then lift $ do
      tok <- newRememberToken
      t <- liftIO getCurrentTime
      storeRememberToken (userId user) tok t
      pure $ Just tok
    else pure Nothing

  pure (user, tok)
