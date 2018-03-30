{-# LANGUAGE OverloadedStrings #-}
module Tests.OIDC.Server.Store.Memory.UserStore
    ( testTree
    ) where

import           Control.Monad                      ((<=<))
import           Data.ByteString                    (ByteString)
import           Data.Maybe                         (isNothing)
import           Data.Semigroup                     ((<>))
import           Data.Text                          (Text)
import qualified Data.UUID                          as UUID

import           Test.Tasty
import           Test.Tasty.HUnit

import           OIDC.Server.Store.Memory.UserStore (initMemoryUserStore)
import           OIDC.Server.Types
    (StoreUserError (..), UserStore (..))
import           OIDC.Types
    (EmailId (..), Password (..), UserAuth (..), UserId (..), Username (..))
import           OIDC.Types.Email
    (parseEmailAddress, toEmailId)

import           Tests.Utils
    (assertLeftEqM', assertRightM')

testTree :: TestTree
testTree = testGroup "Tests.OIDC.Server.Store.Memory.UserStore"
  [ testLookup
  , testStore
  ]


testLookup :: TestTree
testLookup = testCase "Lookup" $ do
  store <- mkStore
  assertEqual "Looks up by UserId" (Just uid1)
     <=< (fmap.fmap) userId $ storeLookupUserById store uid1
  assertEqual "Missing uid is missing" Nothing
     <=< (fmap.fmap) userId $ storeLookupUserById store missingUid

  muser1 <- storeLookupUserById store uid1
  stored1 <- case muser1 of
             Nothing -> assertFailure "User1 not found"
             Just u -> pure u

  user1 <- mkUser1
  assertEqual "Init stores correctly" user1 stored1

testStore :: TestTree
testStore = testCase "Store" $ do
  store <- mkStore
  usr1 <- mkUser1

  assertRightM' "Stores without change"
         $ storeSaveUser store usr1

  let usr2 = usr1 { userUsername = Username "otheruser" }
  _ <- assertLeftEqM' "Check username duplication" DuplicateUsername
         $ storeSaveUser store usr2

  let usr3 = usr1 { userEmailId = EmailId "otheruser@foo.bar" }
  _ <- assertLeftEqM' "Check email duplication" DuplicateEmail
         $ storeSaveUser store usr3

  let usr4 = usr1 { userUsername = Username "new"
                  , userEmailId = EmailId "new@example.com" }
  assertRightM' "Changes email and username"
       $ storeSaveUser store usr4

  musr <- storeLookupUserById store uid1
  assertEqual "Changes are saved" (Just usr4) musr

  assertBool "Old username no longer looks up"
     . isNothing =<< storeLookupUserByUsername store (userUsername usr1)

  assertBool "Old email no longer lookus up"
     . isNothing =<< storeLookupUserByEmail store (userEmailId usr1)



uid1 :: UserId
uid1 = UserId (UUID.fromWords 0 0 0 1)
uid2 :: UserId
uid2 = UserId (UUID.fromWords 0 0 0 2)
uid3 :: UserId
uid3 = UserId (UUID.fromWords 0 0 0 3)
missingUid :: UserId
missingUid = UserId (UUID.fromWords 1 0 0 0)

mkUsr :: (UserId, Text, ByteString, Text) -> IO UserAuth
mkUsr (uid, nm, p, em) = do
    email <- case parseEmailAddress em of
               Nothing -> assertFailure $
                          "Can't parse email " <> show em
               Just r -> pure r
    pure $ UserAuth uid (Username nm) (Password p)
             (toEmailId email) email Nothing

mkUser1 :: IO UserAuth
mkUser1 = mkUsr (uid1, "user1", "pass", "someuser1@example.com")

mkUsers :: IO [UserAuth]
mkUsers = sequence
  [ mkUser1
  , mkUsr (uid2, "otheruser", "pass2", "otheruser@foo.bar")
  , mkUsr (uid3, "thirduser", "pass3", "blah@bar.com")]

mkStore :: IO UserStore
mkStore = initMemoryUserStore =<< mkUsers

{-
data UserAuth = UserAuth
    { userId        :: UserId
    , userUsername  :: Username
    , userPassword  :: Password
    , userEmailId   :: EmailId
    , userEmail     :: EmailAddress
    , userLockedOut :: Maybe UTCTime
    } deriving (Eq, Ord, Show)


-}
