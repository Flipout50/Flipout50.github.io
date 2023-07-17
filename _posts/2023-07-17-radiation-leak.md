---
layout: post
title:  "Radiation Leak"
subtitle: "z3 Crypto Practice Writeup"
date:   2023-07-17
tags: writeups crypto z3
---
This challenge was part of the 2022 US Cyber Open. I played the 2023 game this year and decided to go back and look at some of last year's
challenges. I found one that caught my eye and it looked like a problem for z3. This was perfect because I have been looking for some more
introductory challenges requiring z3 so I could get some practice with it.

# Radiation Leak
## Description
For the past month, your keylogger has been successfully stealing the passcodes for this admin portal (https://metaproblems.com/6f5fa97da7de2648c1531316ebe26954/portal/) for a shady mining company, but they've finally managed to remove your access. They change the code daily. Can you figure out a way to log in now?

Here are the codes (https://metaproblems.com/6f5fa97da7de2648c1531316ebe26954/leaked_tokens.txt) for the previous 30 days and the script they use to generate them (https://metaproblems.com/6f5fa97da7de2648c1531316ebe26954/token_generator.py)

## Solution

### Problem Analysis
First we check out the admin portal.

![](/img/admin_portal.png)
Since they mention we get a previous list of codes I decided not to look into the captcha. Next we download the previous 30 days of codes and the
code generation script. I took a peak at the codes to get a sense of format. We can see that each code is a set of 6 words seperated by a dash.
Now we can dive into the generation script. First the `random` library is imported. The uses it to initialize a 64 byte random seed. The script
also defines a bit mask of 64 1's. The `state_1` variable is set to a random 64-bit value and `state_2` gets set using the previous values
as defined in this line:
```python
state_2 = (state_1 + random.getrandbits(64)) & mask
```

The next bit of code here:
```python
with open("bip39.txt") as f:
    bip = [i for i in f.read().split("\n") if i]
```
defines a list `bip` that opens the file `bip39.txt` and splits the entries by newline and saves each line as an entry in the list.
This is the first little roadblock, as we are not provided with this file. I decided to google `bip39 word list` and this yielded
good results. I realized that the codes were meant to be like the bitcoin recovery phrases. I'm suprised I didn't remember that
from the filename as I have done a few challenges using bip39 in the past. One of the gogle results says
`The Bitcoin Improvement Proposal 39 wordlist (or 'BIP39' for short) is a standardized set of words for the recovery and backup of a bitcoin or cryptocurrency wallet.`
So after poking around a few websites, I found the file on github [here](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt).
The `generate_token()` function looked pretty meaty, so looked at the `convert_to_string()` function next.
It takes in an integer parameter called `token`. It takes the last 11 bits of the token and saves it to a list.
It continues this process taking 11 bits at a time a total of 6 times. Each of these 11 bit chunks is used as an index
for the `bip39` wordlist and combines them with a dash creating the passphrase. Essentially, this function just takes a large number
and uses an algorithm to generate a passphrase from it. In other words, if we get the number, we get the passpharse.
Ok, so the script uses the `generate_token()` function to get theses large numbers and it turens those into passphrases.
Time to look at the `generate_token()` function.

```python
def generate_token():
    global seed, state_1, state_2, mask
    result = seed & mask
    seed >>= 64
    inc = ((result * state_1 + state_2) ^ seed) & mask
    seed |= inc << (7 * 64)
    return result
```

This function takes the last 64 bits of the seed and saves it to `result`. Those 64 bits are then removed from the seed. Then the
`inc` variable is defined as a mathematical combination of `result`, `seed`, `mask`, and the two state variables. Then `seed` is
updated using `inc`. Finally `result` is returned from the function. Ok so what we have on a high level is two variables
holding a "state" which in this case is a 64-bit value, and a seed which gets updated using the states. There are a few important
things to note at this point. First off, the states are never updated. They are defined once a the beginning of the script but
stay static from that point forward. The next thing is that the "tokens" that are turned into passphrases are just the last
64 bits of the value stored in `seed` which gets updated each time based on the state variables. Finally we need to note what
we know and what we don't. We are given the first 30 passphrases that are generated. Since each passphrase is associated with
the `result` gotten from a call to `generate_token()`, we are given the first 30 "results". Recall that `result` is always the
last 64 bits of the seed. Essentially, seed starts completely random, but each of the first 30 times a passphrase is generated,
bits of the `state_1` and `state_2` variables are incorperated into the new seed value, and a part of that value gets leaked to
us in the form of a passphrase. This leaves us with a general gameplan. First, turn the leaked passphrases back into the number
they are associated with. Next, we need to use these leaks to figure out what state variables could've led to such leaks. Finally,
once we recover the state variables and initial seed, we can simply use the existing code to generate what the next passphrase would
be and use it to login to the admin panel.

### Step 1
First at the top of my script I loaded the wordlist into a python list with the same method seen in the challenge script.
```python
with open("bip39.txt") as f:
    bip = [i for i in f.read().split("\n") if i]
```

Then I wrote a function `gen_binary_token(passphrase)` which takes in a passphrase and converts it to a 64 bit bitstring:
```python
def gen_binary_token(passphrase):
    words = passphrase.split('-')
    words = words[::-1] # Reverse order to concatenate binStrings correctly
    bin_token = ''
    for word in words:
        val = bip.index(word)
        bin_chunk = bin(val)[2:].rjust(11, '0')
        bin_token += bin_chunk
    bin_token.rjust(64, '0')
    return bin_token
```
The first line creates a list of each individual word in the passphrase. The words are then reversed because the last 11 bits
of the token are used to created the first word of the passphrase. Then for each word we get its index value in the wordlist
using pythons `.index()` function. Then that number is converted to binary and formatted to have leading zeros so that it is
11 bits long. Then that binary string appended to the `bin_token` variable which will hold to full binary string. After this
is done for every word, the `bin_token` variable is returned. I made two more helper functions for step one, `gen_dataset()`
and `parse_leaked_tokens()`.

```python
def gen_dataset(tokens):
    data = []
    for token in tokens:
        data.append(gen_binary_token(token))
    return data
```
This one takes a list of passphrases and returns a list of the binary tokens for those phrases.

```python
def parse_leaked_tokens(file):
    tokens = []
    for line in file:
        tokens.append(line.rstrip())
    return tokens
```
This function just takes in a file and makes a list of passphrases

Finally there is the driver code for step 1:
```python
leak = open('leaked_tokens.txt', 'r')
tokens = parse_leaked_tokens(leak)
leak.close()
data = gen_dataset(tokens)
```
Now we have our set of leaks and we're ready for step 2!

### Step 2
This is where we need to use z3. It would be an absolute nightmare to try and manually relate the leaked information about the
state variables to the leaked bits of the seed. This is a perfect problem for the z3 constrain solver. If you are unfamiliar,
z3 allows us to feed it a list of constraints on one or more variables that we don't know. Then it uses some black magic
boolean algebra stuff behind the scenes to tell us if there is a solution to what is essentially a HUGE system of equations.
If there is a solution, it can tell what it is, or in the case there is more the one, tell us all possible solutions. This
is a great use of z3 because nothing that happens is too computationally difficult, its mostly just bit manipulation and basic
arithmetic. We import z3 into python with the line
```python
from z3 import*
```

Using the library, I made a function `recover_vars(data)`. This will take in our dataset made in step 1 and generate constraints
using the equaions from the `generate_token()` function given to us. Then it will feed these constraints to z3 and tell it to find
our unknowns, which here are `state_1`, `state_2`, and `seed`. This the complete function:
```python
def recover_vars(data):
    s = Solver()
    int_data = [int(x, 2) for x in data]
    state_1 = BitVec('state_1', 64)
    state_2 = BitVec('state_2', 64)
    seeds = [BitVec(f'seed_{i}', 64 * 8) for i in range(30)]
    
    print("Generating constraints...")
    s.add(state_2 == (state_1 + BitVec('rand_64', 64)) & mask)
    for i, result in enumerate(int_data):
        inc = BitVec(f'inc_{i}', 64*8)
        s.add(result == seeds[i] & mask)
        if i != len(int_data)-1:
            s.add(inc == ZeroExt(64*7, result * state_1 + state_2) ^ LShR(seeds[i], 64))
            s.add(seeds[i+1] == (LShR(seeds[i], 64) | inc << (7*64)))
    print("Contraints generated!")

    print("Solving...")
    print(s.check())
    print("Solving complete!")
    model = s.model()
    s1 = model[state_1].as_long()
    s2 = model[state_2].as_long()
    seed = model[seeds[0]].as_long()
    return (seed, s1, s2)
```

First we create a z3 solver object `s`. Next I convert all the bitstrings that came from the leaked passphrases, "10001011..." for
example, to their integer form in the `int_data` variable. The z3 engine allows us to specify variables of different types. For
our problem, it fits to use the bit vector type `BitVec()` because we will be doing alot of bit level operations like AND, OR,
and bit shifts. We define the state variables as z3 variables using `BitVec('state_1', 64)` and `BitVec('state_2', 64)`. This
creates two z3 bitvectors called 'state_1' and 'state_2' which are both 64 bits. Next I create a list of z3 variables `seeds`.
Since the seed variable gets updated every time a new token is generated, we make a different variable for each iteration of
seed, each 64 bytes long with a name in the form of 'seed_i' where i is the iteration number. We can use the `.add()` methon of
the z3 solver object to add a constraint to the solver. The first one we add is `state_2 == (state_1 + BitVec('rand_64', 64)`.
We got this from when `state_2` was defined in the original problem file. The equation tells z3 that `state_2` must be equal to
`state_1` plus some unknown 64 bit value. Then for each leaked token value, we define a variable `inc_i` which is another 64 byte
value. We add the constraint that the lower 64 bits of the ith seed value is equal to our leak. We also add a constraint on
the `inc_i` variable declaring that it must be created using the given combination of state variables and current seed. Then
we add the constraint that the next seed iteration will be equal to the current seed shifted left by 64 bits and bitwise AND
with `inc_i`. This will result in the solver object `s` having all the relationships between variables in mathematical form.
Then we call `s.check()` which will attempt to solve for the variables and either spit out `sat` for satifiable, meaning there
is at least one solution and z3 has solved the problem, or `unsat` meaning there is not possible variable values that satifies
all the given constraints. The third possiblility is that the program hangs here indefinitely because there is simply too much
math and our computer isn't powerfull enough. Luckily for us, this problem is simple enough that z3 solves it pretty quick.
The next bit of code uses `s.model()` to actually pull the solutions from z3. It uses `.as_long()` to interpret the z3 solved
variables as integers. Then the initial seed, `state_1`, and `state_2` are returned from the function as a tuple. The information
is stored in the main driver code like this:
```python
seed, state_1, state_2 = recover_vars(data)
```

### Step 3
Now that we have the seed and state variables that the website is using to create passphrases, we can predict what the 31'st value
generated will be. I made a function `generate_nth_token(seed, state_1, state_2, n)` that will take in the initial values and return
the nth number that is generated using those values.

```python
def generate_nth_token(seed, state_1, state_2, n):
    for _ in range(n):
        result = seed & mask
        seed >>= 64
        inc = ((result * state_1 + state_2) ^ seed) & mask
        seed |= inc << (7 * 64)
    return result
```
To make this, I basically copy and pasted the part of the code from the challenge script that generated the first 30 phrases, but
instead of generating 30 values, it generates `n` values and returns the nth one from the function. This means we can get the next
token and use the `convert_to_string()` function to get the passphrase the website generated like so:

```python
next_token = generate_nth_token(seed, state_1, state_2, 31)
passphrase = convert_to_string(next_token)
print(f"Next passphrase: {passphrase}")
```

This completes of finished `solve.py` script:
```python
from z3 import *

mask = (1 << 64) - 1

with open("bip39.txt") as f:
    bip = [i for i in f.read().split("\n") if i]
    
def gen_binary_token(passphrase):
    words = passphrase.split('-')
    words = words[::-1] # Reverse order to concatenate binStrings correctly
    bin_token = ''
    for word in words:
        val = bip.index(word)
        bin_chunk = bin(val)[2:].rjust(11, '0')
        bin_token += bin_chunk
    bin_token.rjust(64, '0')
    return bin_token

def gen_dataset(tokens):
    data = []
    for token in tokens:
        data.append(gen_binary_token(token))
    return data

def parse_leaked_tokens(file):
    tokens = []
    for line in file:
        tokens.append(line.rstrip())
    return tokens
    
def recover_vars(data):
    s = Solver()
    int_data = [int(x, 2) for x in data]
    state_1 = BitVec('state_1', 64)
    state_2 = BitVec('state_2', 64)
    seeds = [BitVec(f'seed_{i}', 64 * 8) for i in range(30)]
    
    print("Generating constraints...")
    s.add(state_2 == (state_1 + BitVec('rand_64', 64)) & mask)
    for i, result in enumerate(int_data):
        inc = BitVec(f'inc_{i}', 64*8)
        s.add(result == seeds[i] & mask)
        if i != len(int_data)-1:
            s.add(inc == ZeroExt(64*7, result * state_1 + state_2) ^ LShR(seeds[i], 64))
            s.add(seeds[i+1] == (LShR(seeds[i], 64) | inc << (7*64)))
    print("Contraints generated!")

    print("Solving...")
    print(s.check())
    print("Solving complete!")
    model = s.model()
    s1 = model[state_1].as_long()
    s2 = model[state_2].as_long()
    seed = model[seeds[0]].as_long()
    return (seed, s1, s2)

def convert_to_string(token):
    r = token
    n = []
    for i in range(6):
        n.append(token & 0x7FF)
        token >>= 11
    return "-".join([bip[i] for i in n])
    
def generate_nth_token(seed, state_1, state_2, n):
    for _ in range(n):
        result = seed & mask
        seed >>= 64
        inc = ((result * state_1 + state_2) ^ seed) & mask
        seed |= inc << (7 * 64)
    return result

def main():
    leak = open('leaked_tokens.txt', 'r')
    tokens = parse_leaked_tokens(leak)
    leak.close()
    data = gen_dataset(tokens)
    seed, state_1, state_2 = recover_vars(data)

    print(f"State_1: {state_1}")
    print(f"State_2: {state_2}")
    print(f"Seed: {seed}")

    next_token = generate_nth_token(seed, state_1, state_2, 31)
    passphrase = convert_to_string(next_token)

    print(f"Next passphrase: {passphrase}")
    

if __name__ == '__main__':
    main()
```

### Step 4
Now when we run the program this is the output:
```
Generating constraints...
Contraints generated!
Solving...
sat
Solving complete!
State_1: 336801044331229251
State_2: 10569036738506978277
Seed: 8839961978802441455258413878340373062039297925414226365427229710156238321689408417320578245874950247135846156941309250835199373484350046890129651526955751
Next passphrase: tool-unveil-ranch-soldier-coast-cover
```
As we can see the next passphrase will be `tool-unveil-ranch-soldier-coast-cover` and sure enough when we enter it as a passphrase
and solve the captha the website spits out the flag.

![](/img/radiation_flag.png)

## Flag
`flag{shouldnt_have_used_my_own_number_generator}`
