Relocation section .*
# Ensure there is a dynamic relocation against x
#...
[0-9a-f]+ +[0-9a-f]+ R_.* +_?x(| \+ 0)
#...
Symbol table '.dynsym' contains [0-9]+ entries:
# And ensure the dynamic symbol table contains at least x@VERS.0
# and foo@@VERS.0 symbols
#...
 +[0-9]+: [0-9a-f]+ +(4 +OBJECT +GLOBAL +DEFAULT +[0-9]+ _?x|[0-9]+ +FUNC +GLOBAL +DEFAULT +[0-9]+ _?foo@)@VERS\.0
#...
 +[0-9]+: [0-9a-f]+ +(4 +OBJECT +GLOBAL +DEFAULT +[0-9]+ _?x|[0-9]+ +FUNC +GLOBAL +DEFAULT +[0-9]+ _?foo@)@VERS\.0
#...
Symbol table '.symtab' contains [0-9]+ entries:
#pass
