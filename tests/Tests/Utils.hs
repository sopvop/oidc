module Tests.Utils
  ( throwFailure
  , assertRight
  , assertRightM
  , assertRight'
  , assertRightM'
  , assertLeft
  , assertLeftM
  , assertLeftEq
  , assertLeftEqM
  , assertLeftEq'
  , assertLeftEqM'
  ) where

import           Control.Exception (throwIO)
import           Data.Semigroup    ((<>))
import           Test.Tasty.HUnit  (HUnitFailure (..))


throwFailure :: String -> IO a
throwFailure = throwIO . HUnitFailure

assertRight :: String -> Either a b -> IO b
assertRight txt act = case act of
    Left _ -> throwFailure txt
    Right r -> pure r

assertRightM :: String -> IO (Either a b) -> IO b
assertRightM txt act = act >>= assertRight txt

assertRight' :: Show a => String -> Either a b -> IO b
assertRight' txt act = case act of
    Left e -> throwFailure (txt <> ": " <> show e)
    Right r -> pure r

assertRightM' :: Show a => String -> IO (Either a b) -> IO b
assertRightM' txt act = act >>= assertRight' txt

assertLeft :: String -> Either a b -> IO ()
assertLeft txt act = case act of
  Right _ -> throwFailure txt
  Left _  -> pure ()

assertLeftM :: String -> IO (Either a b) -> IO ()
assertLeftM txt act = act >>= assertLeft txt

assertLeftEq :: Eq a => String -> a -> Either a b -> IO a
assertLeftEq txt expect act = case act of
  Right _ -> throwFailure txt
  Left e | e == expect -> pure e
         | otherwise -> throwFailure txt

assertLeftEqM :: Eq a
               => String
               -> a
               -> IO (Either a b) -> IO a
assertLeftEqM txt expect act =
  act >>= assertLeftEq txt expect

assertLeftEq' :: (Eq a, Show a) => String -> a -> Either a b -> IO a
assertLeftEq' txt expect act = case act of
  Right _ -> throwFailure txt
  Left e | e == expect -> pure e
         | otherwise -> throwFailure (txt <> ": " <> show e)

assertLeftEqM' :: (Show a, Eq a)
               => String
               -> a
               -> IO (Either a b) -> IO a
assertLeftEqM' txt expect act =
  act >>= assertLeftEq' txt expect
