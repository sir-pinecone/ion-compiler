All the C data structures you'll ever need to do almost anything with. You can pretty much solve any
data structure type problem very efficiently both in terms of run time performance and programmer
performance, like productivity.

1. Stretchy buffers (dynamic arrays).
2. Pointer/uintptr hash tables (uintptr -> uintptr).
3. String intern table (string -> uintptr) -- This can be built with the previous two, but you'll
   want this as a primitive).

NOTE: You may not use a <ptr, ptr> hash table that often.
NOTE: This is obviously not an exhaustive list, but it covers a ton of work you tend to do when
      writing low-level code.

## Stretchy Buffer

TODO
TODO
TODO
TODO
TODO

## String Interning

You want to canonicalize different representations of the same string contents.

For example in C, you can have

    char x[] = "asdf";
    char y[] = "asdf";

These both point to different addresses in memory. They cannot share memory because they're distinct
objects.

If you want to check equality then you have to do something like this:

    // Linear time in min(strlen(x), strlen(y))
    if (strcmp(x, y) == 0) {
        // ...
    }

By walking them and verifying that they're the same length and that a null-terminator exists in the
same place in both, so that one is not just a prefix of the other.

So string interning is the idea that you have some function, e.g.

    const char *StrIntern(const char *str);

and it has the property

    StrIntern(x) == StrIntern(y) iff strcmp(x, y) == 0   (equal as strings)

What does this do? It takes an arbitrary null-terminated c-string buffer (although you often want a
version that can work on sub strings) and it returns a stable pointer that is a canonical
representation of that string content.

So if you start your program with `StrIntern("foo")`, it will check to see if it's seen that string
yet, but it hasn't, so it'll make a copy and return a pointer to that copy. Then the next time you
call the intern function with a string buffer containing "foo", it will return that same canonical
pointer to you. The pointer needs to be stable, as in, it should not change over the lifetime of
the program unless that's something you account for and update references.

### Why is it Useful?

Simply put, once you've interned a string buffer, you can do string equality by just using pointer
equality. This is great, even with the cost you pay when interning a string since it has to do
character-by-character matching to find an existing entry (can be accelerated up with a hash table).
The pointer equality test is a lot faster than always having to walk strings when checking for
equality.

This simplifies your code: less code to write, less error prone. And it has a very nice feature that
almost all true parsing happens at the boundary of the system. Input comes into the system via
files, user input, etc. and at the point of entry there is a hard boundary where the string buffer
crosses and turns into a canonical string pointer. Now all of the code inside the boundary can agree
that its working with canonicalized strings, so it just has to operate on opaque pointers rather
than string values.

You tend to want to intern smaller strings. It's great for parsers that need to store programming
language identifiers and similar things. Any time you're doing symbol table lookups in you compiler
to resolve variable references to variable definitions, at that point you're not actually doing
string lookups, you're doing pointer lookups.

This becomes even more powerful when combined with a pointer hash table. You can easily build a
symbol table by interning at read time in the lexer and then when doing name resolution, you do a
pointer lookup in the hash table. I don't know for sure yet, but I think this is a <ptr, ptr> table
with the key being the intern string pointer and the value being some other pointer relevant to the
symbol.
