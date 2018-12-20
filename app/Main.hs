module Main where

import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as C
import           Data.ByteString (ByteString)
import           Data.ByteString.Internal

import Data.Maybe
import Data.Elf

import Foreign.C
import Foreign.Ptr
import Foreign.Marshal.Utils

import Data.Word
import Data.Bits

import Control.Exception
import Control.Monad
import Control.Applicative

import System.Process

import Proc

foreign import ccall "getauxval" c_getauxval :: CInt -> IO (Ptr ())
foreign import ccall "personality" c_personality :: CLong -> IO CInt
foreign import ccall "mprotect" c_mprotect :: Ptr () -> CSize -> CInt -> IO CInt

disableASLR :: IO ()
disableASLR = do
  throwErrnoIfMinus1 "personality" $! c_personality 0x40000
  return ()

vdsoGetEhdr :: IO Int
vdsoGetEhdr = do
  vdso <- c_getauxval 0x21
  return $! fromIntegral . ptrToIntPtr $ vdso

vdsoGetMapping :: IO ProcMapEntry
vdsoGetMapping = do
  let mapsFile = "/proc/self/maps"
  mapping <- S.readFile mapsFile
  case parseProcMap mapping of
    Left err -> error $! "unable to parse " ++ mapsFile ++ " " ++ show err
    Right parsed -> case filter (\e -> procMapName e == Just "[vdso]") parsed of
      [] -> error $! "cannot find vdso mapping, is vdso enabled?"
      (vdso:_) -> return vdso

fromPerms :: [ProcMapPerm] -> CInt
fromPerms = foldl go 0
  where
    go r ProcMapPermRead  = r .|. 1
    go r ProcMapPermWrite = r .|. 2
    go r ProcMapPermExec  = r .|. 4
    go r _                = r

procSetPerms perms mapping =
    throwErrnoIfMinus1_ "mprotect" $ c_mprotect ( (intPtrToPtr . fromIntegral . procMapBase) mapping) ( (fromIntegral . procMapSize) mapping) (fromPerms perms)

procPermSetWritable :: ProcMapEntry -> IO ()
procPermSetWritable mapping = unless (ProcMapPermWrite `elem` procMapPerms mapping) $ do
  procSetPerms (ProcMapPermWrite : perms) mapping
  where perms = procMapPerms mapping

procPermRestore :: ProcMapEntry -> IO ()
procPermRestore mapping = procSetPerms (procMapPerms mapping) mapping

withWritableMapping mapping f = bracket (procPermSetWritable mapping >> return mapping) procPermRestore f

withWritableVdso f = do
  vdsoMap <- vdsoGetMapping
  withWritableMapping vdsoMap f

vdsoGet :: IO ByteString
vdsoGet = do
  disableASLR
  vdsoMap <- vdsoGetMapping
  S.packCStringLen (intPtrToPtr . fromIntegral . procMapBase $ vdsoMap, procMapSize vdsoMap)

vdsoParseSymbolTable = join . parseSymbolTables

vdsoLookupSymbolTable :: String -> [ElfSymbolTableEntry] -> Maybe ElfSymbolTableEntry
vdsoLookupSymbolTable sym = listToMaybe . filter (\e -> (snd . steName) e == Just (C.pack sym) )

getSymbolValue :: String -> [ElfSymbolTableEntry] -> Maybe (Word64, Int)
getSymbolValue sym = fmap (\x -> (steValue x, (fromIntegral . steSize) x)) . vdsoLookupSymbolTable sym

__vdso_time, __vdso_clock_gettime, __vdso_getcpu, __vdso_gettimeofday :: ByteString
__vdso_time = S.pack [ 0xb8, 0xc9, 0x0, 0x0, 0x0                   -- mov %SYS_time, %eax
                     , 0x0f, 0x05                                  -- syscall
                     , 0xc3                                        -- retq
                     , 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00    -- nopl 0x0(%rax, %rax, 1)
                     , 0x00 ]

__vdso_clock_gettime = S.pack [ 0xb8, 0xe4, 0x00, 0x00, 0x00                -- mov SYS_clock_gettime, %eax
                              , 0x0f, 0x05                                  -- syscall
                              , 0xc3                                        -- retq
                              , 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00    -- nopl 0x0(%rax, %rax, 1)
                              , 0x00 ]

__vdso_getcpu = S.pack [ 0x48, 0x85, 0xff                                   -- test %rdi, %rdi
                       , 0x74, 0x06                                         -- je ..
                       , 0xc7, 0x07, 0x00, 0x00, 0x00, 0x00                 -- movl $0x0, (%rdi)
                       , 0x48, 0x85, 0xf6                                   -- test %rsi, %rsi
                       , 0x74, 0x06                                         -- je ..
                       , 0xc7, 0x06, 0x00, 0x00, 0x00, 0x00                 -- movl $0x0, (%rsi)
                       , 0x31, 0xc0                                         -- xor %eax, %eax
                       , 0xc3                                               -- retq
                       , 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00 ]         -- nopl 0x0(%rax)

__vdso_gettimeofday = S.pack [ 0xb8, 0x60, 0x00, 0x00, 0x00                 -- mov SYS_gettimeofday, %eax
                             , 0x0f, 0x05                                   -- syscall
                             , 0xc3                                         -- retq
                             , 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00     -- nopl 0x0(%rax, %rax, 1)
                             , 0x00 ]

__vdso_funcs = [ ("__vdso_clock_gettime", __vdso_clock_gettime)
               , ("__vdso_getcpu", __vdso_getcpu)
               , ("__vdso_gettimeofday", __vdso_gettimeofday)
               , ("__vdso_time", __vdso_time) ]

lookupVdsoSymbols :: Elf -> [ (String, (Word64, Int) ) ]
lookupVdsoSymbols elf = catMaybes . map (\sym -> liftA2 (,) (Just sym) (getSymbolValue sym symTabs)) $ vdsoSyms
  where
    symTabs  = vdsoParseSymbolTable elf
    vdsoSyms = map fst __vdso_funcs

doUpdateMap :: Word64 -> Word64 -> Int -> ByteString -> IO ()
doUpdateMap la base size bs = do
  let ptr = (intPtrToPtr . fromIntegral) (la + base)
  S.useAsCStringLen bs $ \(s, n) ->
    moveBytes ptr s (min size n)

updateVdso :: IO ()
updateVdso = do
  disableASLR
  la <- vdsoGetEhdr
  withWritableVdso $ \vdsoMap -> do
    vdso <- S.packCStringLen (intPtrToPtr . fromIntegral . procMapBase $ vdsoMap, procMapSize vdsoMap)
    S.putStr vdso
    let vv = lookupVdsoSymbols (parseElf vdso)
    mapM_ (\(name, (base, size)) ->
             case lookup name __vdso_funcs of
               Nothing -> return ()
               Just bs -> doUpdateMap (fromIntegral la) base size bs) vv

foreign import ccall "time" c_time :: Ptr CInt -> IO CInt

callSysTime :: IO CInt
callSysTime = do
  throwErrnoIfMinus1 "time" $ c_time nullPtr

main :: IO ()
main = do
  updateVdso
  callSysTime >>= print
