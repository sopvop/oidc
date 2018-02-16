module Tests.Utils
  ( assertRight
  , assertRightM
  , assertRight'
  , assertRightM'
  , throwFailure
  ) where

import           Control.Exception (throwIO)
import           Data.Semigroup    ((<>))
import           Test.Tasty.HUnit  (HUnitFailure (..))


assertRight :: String -> Either a b -> IO b
assertRight txt act = case act of
    Left _ -> throwFailure txt
    Right r -> pure r

assertRightM :: String -> IO (Either a b) -> IO b
assertRightM txt act = do
  r <- act
  assertRight txt r

assertRight' :: Show a => String -> Either a b -> IO b
assertRight' txt act = case act of
    Left e -> throwFailure (txt <> ": " <> show e)
    Right r -> pure r

assertRightM' :: Show a => String -> IO (Either a b) -> IO b
assertRightM' txt act = do
  r <- act
  assertRight' txt r


throwFailure :: String -> IO a
throwFailure = throwIO . HUnitFailure
