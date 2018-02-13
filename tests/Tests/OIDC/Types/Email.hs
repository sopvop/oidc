{-# LANGUAGE OverloadedStrings #-}
module Tests.OIDC.Types.Email
  ( testTree
  ) where

import           Control.Exception (throwIO)
import           Data.Semigroup    ((<>))
import           Data.Text         (Text)
import           Test.Tasty
import           Test.Tasty.HUnit

import           OIDC.Types.Email


testTree :: TestTree
testTree = testGroup "Tests.OIDC.Types.Email"
    [ testStripping
    ]

assertParses :: Text -> IO EmailAddress
assertParses a = case parseEmailAddress a of
  Nothing -> throwIO . HUnitFailure $ "Can't parse: " <> show a
  Just addr -> pure addr

testStripping :: TestTree
testStripping = testCase "stripping" $ do
  addrSimple <- assertParses "foo@example.com"
  addrPlus <- assertParses "foo1+extra@example.com"
  addrDots <- assertParses "foo2.bar@example.com"
  addrDotsPlus <- assertParses "foo3.bar+extra.baz@example.com"

  assertEqual "simple" (EmailId "foo@example.com")
              $ toEmailId addrSimple
  assertEqual "pluses" (EmailId "foo1@example.com")
              $ toEmailId addrPlus
  assertEqual "dots" (EmailId "foo2bar@example.com")
              $ toEmailId addrDots
  assertEqual "pluses and dots" (EmailId "foo3bar@example.com")
              $ toEmailId addrDotsPlus

  pure ()
