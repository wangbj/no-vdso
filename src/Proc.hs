module Proc (
    ProcMapPerm  (..)
  , ProcMapEntry (..)
  , procMapDevMajor
  , procMapDevMinor
  , parseProcMapEntry
  , parseProcMap
  ) where

import qualified Data.ByteString.Char8 as C
import           Data.ByteString (ByteString)

import Text.Parsec
import Control.Monad.Identity
import Control.Monad
import Data.Word
import Data.Bits

import Numeric

data ProcMapPerm = ProcMapPermRead
                 | ProcMapPermWrite
                 | ProcMapPermExec
                 | ProcMapPermPrivate
                  deriving (Show, Eq)

data ProcMapEntry = ProcMapEntry {
    procMapBase   :: Word64
  , procMapSize   :: Int
  , procMapPerms  :: [ProcMapPerm]
  , procMapOffset :: Int
  , procMapDev    :: Int
  , procMapInode  :: Int
  , procMapName   :: Maybe String
  } deriving (Show, Eq)

procMapDevMajor :: Int -> Int
procMapDevMajor dev = (fromIntegral dev) `shiftR` 8

procMapDevMinor :: Int -> Int
procMapDevMinor dev = (fromIntegral dev) .&. 0xff

hexP :: (Integral a, Monad m) => ParsecT String u m a
hexP = do
  digits <- many1 hexDigit
  case readHex digits of
    [] -> parserFail $! "failed to readHex " ++ digits
    ((x, _):_) -> return x

permsP :: Monad m => ParsecT String u m [ProcMapPerm]
permsP = do
  let ptn = zip "rwxp" [ProcMapPermRead, ProcMapPermWrite, ProcMapPermExec, ProcMapPermPrivate]
      over ( (c, p), x) r
        | c == x = p:r
        | c /= x = r
  p <- count 4 (oneOf "rwxp-")
  return $! foldr over [] (zip ptn p)

sectionP :: Monad m => ParsecT String u m (Word64, Word64)
sectionP = do
  base <- hexP
  char '-'
  end  <- hexP
  return (fromIntegral base, fromIntegral end)

devP :: Monad m => ParsecT String u m Int
devP = do
  major <- hexP
  char ':'
  minor <- hexP
  return $! major `shiftL` 8 .|. minor

parserP :: Monad m => ParsecT String u m ProcMapEntry
parserP = do
  (start, end) <- sectionP
  void spaces
  perms <- permsP
  void spaces
  offset <- hexP
  spaces
  dev <- devP
  spaces
  inode <- hexP
  spaces
  name <- option Nothing (Just <$> (many1 anyChar))
  return $! ProcMapEntry start (fromIntegral (end-start)) perms offset dev inode name

parseProcMapEntry :: ByteString -> Either ParseError ProcMapEntry
parseProcMapEntry = runIdentity .  runParserT parserP 0 "<stdin>" . C.unpack

parseProcMap :: ByteString -> Either ParseError [ProcMapEntry]
parseProcMap = mapM parseProcMapEntry . C.lines
