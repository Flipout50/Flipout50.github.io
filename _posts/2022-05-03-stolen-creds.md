---
layout: post
title:  "Stolen Creds"
subtitle: "Simulations Arcade Hack CTF hash challenge"
date:   2022-05-03
tags: writeups crypto
---
Here's another writeup for a challenge at Simulations Arcade Hack CTF. This challenge was pretty cool and boiled down to making a python script to generate a custom
wordlist and using it to crack a password hash. Very Fun!
# Stolen Creds (Unknown Solves, 100 points)
## Description
We’ve gotten a copy of Cerby’s creds, but his password is really weird. Can you take a look and see if you can figure it out?

We know his password was his first name + pets name + Year born + favorite symbol.

Hint: It's double fried dbfebaf52f9f55e6d2519e253e721063

## Solution
Ok so we've got what appears to be a password hash that belongs to Cerby, and we need to find what the plaintext password is. If you don't know what a hash is, it's
essentially a one-way encryption algorithm. They are used to prevent plaintext passwords from being stored on website databases for added security in the event of a 
data breach. They also have some computer forensics applications as well. You can read more about them [here](https://medium.com/@cmcorrales3/password-hashes-how-they-work-how-theyre-hacked-and-how-to-maximize-security-e04b15ed98d).

The first step in cracking a hash is to determine the algorithm used to hash the password. I'm pretty familiar with hashes in a ctf context so I was pretty sure this
was MD5 but I use a cmdline tool called [hashid](https://github.com/psypanda/hashID). Running ``hashid dbfebaf52f9f55e6d2519e253e721063`` gives us these results:
```
Analyzing 'dbfebaf52f9f55e6d2519e253e721063'
[+] MD2
[+] MD5
[+] MD4
[+] Double MD5
[+] LM
[+] RIPEMD-128
[+] Haval-128
[+] Tiger-128
[+] Skein-256(128)
[+] Skein-512(128)
[+] Lotus Notes/Domino 5
[+] Skype
[+] Snefru-128
[+] NTLM
[+] Domain Cached Credentials
[+] Domain Cached Credentials 2
[+] DNSSEC(NSEC3)
[+] RAdmin v2.x
```
Hashes at the top are more likely to be the algorithm used than the others, but ``MD2`` and ``MD4`` are fairly uncommon so I stuck with my ``MD5`` intuition. If we
remember back to the hint given with the challenge ``It's double fried``, ``Double MD5`` makes the most sense. This just means that the hash was created by hashing
the plaintext password with MD5, then hashing the result a second time with MD5 again. Now that we know what algorithm was used, we need to crack the hash.

Hashes are cracked typically in two ways
* Checking a list of precomputed password hashes against the target hash (AKA Rainbow Tables)
* Computing the hashes of many possible passwords from a wordlist and waiting until we find a match

Although option one has the potential to be faster, we know this password will be specific to Cerby, so the odds of his password being on some Rainbow Table is very low.
In order to try option two, we are going to need a wordlist. If you remember, they actually gave us a formula that Cerby uses for his passwords! If we generate a
wordlist of all passwords that fit this formula, then we can use that wordlist to crack the hash with a hash cracking tool like [John the Ripper](https://www.openwall.com/john/). On to wordlist generation!

Alright, let's go over the password formula again. We are told the password is ``first name + pets name + Year born + favorite symbol``. Well we know the first name is
Cerby so the password starts with that. The pets name is probably the hardest thing to guess, but most people have common pet names. I found [this website](https://7esl.com/dog-names/)
and threw all the names into a python list. Next we need the year of birth. In reality this is just a 4 digit number, but I went ahead and assumed Cerby was born after 1900.
Finally, his favorite symbol, so I typed every symbol I could find on my keyboard into a string: ``symbols = "!@#$%^&*()_-+=/?[]{}`~><.,"``. Now its time to make
a python boilerplate with our data.
```python
def genYears(start, end):
    years = []
    for year in range(start, end+1):
        years.append(str(year))
    return years

petNames = ["Ace", "Elvis", "Peanut", "Otis", "Apollo", "Finn", "Bailey", "Frankie", "Prince", "Bandit", "George", "Rex", "Baxter", "Gizmo", "Riley", "Bear", "Gunner", "Rocco", "Beau", "Gus", "Rocky", "Benji", "Hank", "Romeo", "Benny", "Harley", "Rosco", "Bently", "Henry", "Rudy", "Blue", "Hunter", "Rufus", "Bo", "Jack", "Rusty", "Boomer", "Ralph", "Ted", "Ben", "Jackson", "Sam", "Brady", "Jake", "Sammy", "Brody", "Jasper", "Samson", "Bruno", "Scooter", "Jax", "Brutus", "Joey", "Scout", "Bubba", "Coby", "Shadow", "Buddy", "Leo", "Simba", "Buster", "Loki", "Sparky", "Cash", "Louis", "Spike", "Champ", "Lucky", "Tank", "Chance", "Luke", "Teddy", "Charlie", "Patch", "Merlin", "Hector", "Dave", "Boris", "Basil", "Rupert", "Mack", "Thor", "Chase", "Marley", "Rolo", "Aries", "Leo", "Axel", "Barkley", "Toby", "Chester", "Max", "Bingo", "Tucker", "Chico", "Blaze", "Mickey", "Tyson", "Coco", "Bubba", "Chip", "Butch", "Chief", "Milo", "Vader", "Cody", "Buck", "Clifford", "Dodge", "Moose", "Winston", "Cooper", "Murphy", "Abbott", "Diego", "Goose", "Dane", "Fisher", "Yoda", "Copper", "Oliver", "Zeus", "Abe", "Dexter", "Ollie", "Aero", "Bones", "Digger", "Waffle", "Ziggy", "Aj", "Diesel", "Oreo", "Duke", "Oscar", "Angus", "Barney", "Bella", "Lola", "Luna", "Poppy", "Coco", "Ruby", "Molly", "Daisy", "Millie", "Rosie", "India", "Lucy", "Anna", "Cookie", "Pepper", "Biscuit", "Lily", "Bonnie", "Tilly", "Willow", "Roxy", "Nala", "Maisie", "Honey", "Penny", "Katy", "Fleur", "Mimi", "Mia", "Lexi", "Holly", "Bailey", "Skye", "Lulu", "Belle", "Skye", "Dolly", "Lottie", "Minnie", "Ellie", "Jess", "Betty", "Winnie", "Amber", "Sweetie", "Diamond", "Hetty", "Missy", "Mabel", "Sasha", "Cassie", "Jessie", "Sindy", "Sugar", "Ella", "Peggy", "Meg", "Misty", "Summer", "Maya", "Tess", "Izzy", "Evie", "Betsy", "Stella", "Muffin", "Pandora", "Nell", "Shelby", "Paris", "Phoebe", "Sophie", "Mitzy", "Tia", "Sage", "Peaches", "Darcey", "Jasmine", "Kali", "Pearl", "Raven", "Princess", "Pip", "Jade", "Opal", "Precious", "Sissy", "Liberty", "Marnie", "Matilda", "Lady", "Frankie", "Olive", "Maddie", "Nellie", "Harley", "Elsa", "Beau", "Mocha", "Dora", "Cleo", "Juno", "Dotty", "Morgan", "Pixie", "Ivy", "Freya", "Nina", "Margot", "Angel", "Sadie", "Sally", "Pebbles", "Suki", "Kiki", "Boo", "Star", "Zara", "Mopsi", "Flopsi"]    
firstName = "Cerby"
symbols = "!@#$%^&*()_-+=/?[]{}`~><.,"
years = genYears(1900, 2022)
```
The ``genYears()`` function just returns a list of years as strings. Now if we create a nested ``for`` loop iterating through all these components, we can generate
passwords using the formula ``password = firstName + pet + year + symbol``. We can write each of these passwords to a file and we have a custom wordlist! The final
script is below:
```python
def genYears(start, end):
    years = []
    for year in range(start, end+1):
        years.append(str(year))
    return years

petNames = ["Ace", "Elvis", "Peanut", "Otis", "Apollo", "Finn", "Bailey", "Frankie", "Prince", "Bandit", "George", "Rex", "Baxter", "Gizmo", "Riley", "Bear", "Gunner", "Rocco", "Beau", "Gus", "Rocky", "Benji", "Hank", "Romeo", "Benny", "Harley", "Rosco", "Bently", "Henry", "Rudy", "Blue", "Hunter", "Rufus", "Bo", "Jack", "Rusty", "Boomer", "Ralph", "Ted", "Ben", "Jackson", "Sam", "Brady", "Jake", "Sammy", "Brody", "Jasper", "Samson", "Bruno", "Scooter", "Jax", "Brutus", "Joey", "Scout", "Bubba", "Coby", "Shadow", "Buddy", "Leo", "Simba", "Buster", "Loki", "Sparky", "Cash", "Louis", "Spike", "Champ", "Lucky", "Tank", "Chance", "Luke", "Teddy", "Charlie", "Patch", "Merlin", "Hector", "Dave", "Boris", "Basil", "Rupert", "Mack", "Thor", "Chase", "Marley", "Rolo", "Aries", "Leo", "Axel", "Barkley", "Toby", "Chester", "Max", "Bingo", "Tucker", "Chico", "Blaze", "Mickey", "Tyson", "Coco", "Bubba", "Chip", "Butch", "Chief", "Milo", "Vader", "Cody", "Buck", "Clifford", "Dodge", "Moose", "Winston", "Cooper", "Murphy", "Abbott", "Diego", "Goose", "Dane", "Fisher", "Yoda", "Copper", "Oliver", "Zeus", "Abe", "Dexter", "Ollie", "Aero", "Bones", "Digger", "Waffle", "Ziggy", "Aj", "Diesel", "Oreo", "Duke", "Oscar", "Angus", "Barney", "Bella", "Lola", "Luna", "Poppy", "Coco", "Ruby", "Molly", "Daisy", "Millie", "Rosie", "India", "Lucy", "Anna", "Cookie", "Pepper", "Biscuit", "Lily", "Bonnie", "Tilly", "Willow", "Roxy", "Nala", "Maisie", "Honey", "Penny", "Katy", "Fleur", "Mimi", "Mia", "Lexi", "Holly", "Bailey", "Skye", "Lulu", "Belle", "Skye", "Dolly", "Lottie", "Minnie", "Ellie", "Jess", "Betty", "Winnie", "Amber", "Sweetie", "Diamond", "Hetty", "Missy", "Mabel", "Sasha", "Cassie", "Jessie", "Sindy", "Sugar", "Ella", "Peggy", "Meg", "Misty", "Summer", "Maya", "Tess", "Izzy", "Evie", "Betsy", "Stella", "Muffin", "Pandora", "Nell", "Shelby", "Paris", "Phoebe", "Sophie", "Mitzy", "Tia", "Sage", "Peaches", "Darcey", "Jasmine", "Kali", "Pearl", "Raven", "Princess", "Pip", "Jade", "Opal", "Precious", "Sissy", "Liberty", "Marnie", "Matilda", "Lady", "Frankie", "Olive", "Maddie", "Nellie", "Harley", "Elsa", "Beau", "Mocha", "Dora", "Cleo", "Juno", "Dotty", "Morgan", "Pixie", "Ivy", "Freya", "Nina", "Margot", "Angel", "Sadie", "Sally", "Pebbles", "Suki", "Kiki", "Boo", "Star", "Zara", "Mopsi", "Flopsi"]    
firstName = "Cerby"
symbols = "!@#$%^&*()_-+=/?[]{}`~><.,"
years = genYears(1900, 2022)

with open('./passwords.txt', 'w') as wordlist:
    for pet in petNames:
        for year in years:
            for symbol in symbols:
                password = firstName + pet + year + symbol
                print(password)
                wordlist.write(password + "\n")

print("Wordlist Generated")
```

We now have every component we need to crack the hash. We know the algorithm is ``Double MD5``, and we have a list of possible passwords we generated with python.
I then fed [John the Ripper](https://www.openwall.com/john/) the information and let him go to work. The general command format for password cracking with john
is ``john --format=[hash format] --wordlist=[possible passwords file] [file containing hash to crack]``. Unfortunately for us, ``Double MD5`` isn't a default 
hash format built into john, but john has a really cool feature that allows us to specify a custom algorithm. We can accomplish this using the ``-form=dynamic=``
option. Since ``Double MD5`` is just two cycles of ``MD5``, our format is ``md5(md5($p))``. We can specify our wordlist with ``--wordlist=./passwords.txt`` and I
pasted the given hash into a file called ``hash``. Now we just need to put it all together and run our final command: ``john -form=dynamic='md5(md5($p))' --wordlist=./passwords.txt hash``
![image](/img/cracked.png)
As we can see, john found the password ``CerbyToby1901*``!

## Flag
``SAH{CerbyToby1901*}``
