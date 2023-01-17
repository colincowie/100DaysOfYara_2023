rule mal_crypto_stealer_patterns {
  meta:
    author = "Colin Cowie"
    description = "Detects regex patterns used by clipboard stealers"
    reference ="Sample: 0cce0590ca8cc4fce97f3b4f2d270c80e65d81c6. Further info: https://github.com/avast/ioc/tree/master/ViperSoftX"
  strings:
      $btc1 = { 5e 62 63 31 5b 61 2d 7a 30 2d 39 5d 7b 33 39 2c 35 39 7d 24 } 
      $btc2 = { 5e 31 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 31 2d 39 5d 7b 32 36 2c 33 33 7d 24 } 
      $btc3 ={ 5e 33 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 31 2d 39 5d 7b 32 36 2c 33 33 7d 24 } 
      $bch = { 5e 28 28 62 69 74 63 6f 69 6e 63 61 73 68 7c 62 63 68 72 65 67 7c 62 63 68 74 65 73 74 29 3a 29 3f 28 71 7c 70 29 5b 61 2d 7a 30 2d 39 5d 7b 34 31 7d 24 } 
      $bnb = { 5e 28 62 6e 62 29 28 5b 61 2d 7a 30 2d 39 5d 7b 33 39 7d 29 24 }
      $eth = { 5e 30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d 24 }
      $xmr = { 5e 5b 34 38 5d 5b 30 2d 39 41 42 5d 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 39 33 7d 24 } 
      $xrp = { 5e 72 5b 72 70 73 68 6e 61 66 33 39 77 42 55 44 4e 45 47 48 4a 4b 4c 4d 34 50 51 52 53 54 37 56 57 58 59 5a 32 62 63 64 65 43 67 36 35 6a 6b 6d 38 6f 46 71 69 31 74 75 76 41 78 79 7a 5d 7b 32 34 2c 33 34 7d 24 20 20 } 
      $dash = { 5e 58 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 33 33 7d 24} 
  condition:
      2 of them
}