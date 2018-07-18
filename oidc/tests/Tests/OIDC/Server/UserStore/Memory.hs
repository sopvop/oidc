{-# LANGUAGE OverloadedStrings #-}
module Tests.OIDC.Server.UserStore.Memory
    ( testTree
    ) where

import           Control.Monad ((<=<))
import           Data.ByteString (ByteString)
import           Data.Maybe (fromJust, isNothing)
import           Data.Semigroup ((<>))
import           Data.Text (Text)
import           Data.Time (UTCTime (..), addUTCTime, fromGregorian)
import qualified Data.UUID as UUID

import           Test.Tasty
import           Test.Tasty.HUnit

import           OIDC.Server.UserStore
    (RememberToken (..), StoreUserError (..), UserStore (..))
import           OIDC.Server.UserStore.Memory (initUserStore)
import           OIDC.Types
    (EmailStatus (..), Password (..), UserAuth (..), UserId (..),
    Username (..))
import           OIDC.Types.Email (parseEmailAddress)

import           Tests.Utils (assertLeftEqM', assertRightM')

testTree :: TestTree
testTree = testGroup "Tests.OIDC.Server.UserStore.Memory"
  [ testLookup
  , testStore
  , testRememberToken
  ]


testLookup :: TestTree
testLookup = testCase "Lookup" $ do
  store <- mkStore
  assertEqual "Looks up by UserId" (Just uid1)
     <=< (fmap.fmap) userId $ usLookupUserById store uid1
  assertEqual "Missing uid is missing" Nothing
     <=< (fmap.fmap) userId $ usLookupUserById store missingUid

  muser1 <- usLookupUserById store uid1
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
         $ usSaveUser store usr1

  let usr2 = usr1 { userUsername = Username "otheruser" }
  _ <- assertLeftEqM' "Check username duplication" DuplicateUsername
         $ usSaveUser store usr2

  let usr3 = usr1 { userEmail = fromJust $ parseEmailAddress "otheruser@foo.bar" }
  _ <- assertLeftEqM' "Check email duplication" DuplicateEmail
         $ usSaveUser store usr3

  let usr4 = usr1 { userUsername = Username "new"
                  , userEmail = fromJust $ parseEmailAddress "new@example.com" }
  assertRightM' "Changes email and username"
       $ usSaveUser store usr4

  musr <- usLookupUserById store uid1
  assertEqual "Changes are saved" (Just usr4) musr

  assertBool "Old username no longer looks up"
     . isNothing =<< usLookupUserByUsername store (userUsername usr1)

  assertBool "Old email no longer lookus up"
     . isNothing =<< usLookupUserByEmail store (userEmail usr1)



testRememberToken :: TestTree
testRememberToken = testCase "RememberToken" $ do
  store <- mkStore
  usr1 <- mkUser1

  let
    tok1 = RememberToken "tok1"
    usrid1 = userId usr1
    t0 = UTCTime (fromGregorian 2018 01 01) 0

  usStoreRememberToken store usrid1 tok1 t0

  got1 <- usLookupByRememberToken store usrid1 tok1 (addUTCTime (-1000) t0)
  assertEqual "Token was saved" (Just usr1) got1

  got2 <- usLookupByRememberToken store usrid1 tok1 (addUTCTime 1000 t0)
  assertEqual "Token timed out" Nothing got2

  got3 <- usLookupByRememberToken store usrid1 tok1 (addUTCTime (-1000) t0)
  assertEqual "Timed out token removed from store" Nothing got3

  usStoreRememberToken store missingUid tok1 t0
  got4 <- usLookupByRememberToken store usrid1 tok1 (addUTCTime (-1000) t0)
  assertEqual "Token not saved for missing user" Nothing got4


  pure ()

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
           email EmailUnverified Nothing
           "" nm  Nothing (UTCTime (fromGregorian 2018 01 01) 0)

mkUser1 :: IO UserAuth
mkUser1 = mkUsr (uid1, "user1", "pass", "someuser1@example.com")

mkUsers :: IO [UserAuth]
mkUsers = sequence
  [ mkUser1
  , mkUsr (uid2, "otheruser", "pass2", "otheruser@foo.bar")
  , mkUsr (uid3, "thirduser", "pass3", "blah@bar.com")]

mkStore :: IO UserStore
mkStore = initUserStore =<< mkUsers

