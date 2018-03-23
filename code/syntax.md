# The ion Grammar

## Grouping tokens:

( ) [ ] { }

## Unary operators:

+ - ! ~ & *

## Binary operators:

LSHIFT = '<<'
RSHIFT = '>>'
EQ     = ' =='
NOT_EQ = '!='
LT_EQ  = '<='
GT_EQ  = '>='
AND    = '&&'
OR     = '||'

+ - | ^ LSHIFT RSHIFT
* / % &
EQ NOT_EQ < > LT_EQ GT_EQ
AND
OR
? :

## Assignment operators:

=

COLON_ASSIGN  = ': ='
ADD_ASSIGN    = '+ ='
SUB_ASSIGN    = '- ='
OR_ASSIGN     = '| ='
XOR_ASSIGN    = '^ ='
LSHIFT_ASSIGN = '<<='
RSHIFT_ASSIGN = '>>=
MUL_ASSIGN    = '* ='
DIV_ASSIGN    = '/ ='
MOD_ASSIGN    = '%='

## Names / literals:

NAME = [a-zA-Z_][a-zA-Z0-9_]*
INT  = [1-9][0-9]* | 0[xX][0-9a-fA-F]+
CHAR = '\'' . '\''
STR  = '"' [^"]* '"'
