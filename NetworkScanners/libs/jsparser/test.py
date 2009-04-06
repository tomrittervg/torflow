import antlr3
from JavaScriptLexer import JavaScriptLexer
from JavaScriptParser import JavaScriptParser

class ParseError(Exception): 
  def __init__(self, tokens, e):
    self.tokens = tokens
    self.e = e

class LexerError(Exception): 
  def __init__(self, tokens, e):
    self.tokens = tokens
    self.e = e

class ExceptionalJSParser(JavaScriptParser):
  def displayRecognitionError(self, tokens, e): raise ParseError(tokens, e) 
class ExceptionalJSLexer(JavaScriptLexer):
  def displayRecognitionError(self, tokens, e): raise LexerError(tokens, e) 

input = 'var foo = function() { var foo = "h\'i"; return foo+2; };'
char_stream = antlr3.ANTLRStringStream(input)
# or to parse a file:
# char_stream = antlr3.ANTLRFileStream(path_to_input)
# # or to parse an opened file or any other file-like object:
# char_stream = antlr3.ANTLRInputStream(file)
                                                                                
lexer = ExceptionalJSLexer(char_stream)
tokens = antlr3.CommonTokenStream(lexer)
parser = ExceptionalJSParser(tokens)
try:
  program = parser.program()
  print str(program.tree)+" -> "+str(program.tree.getType())
  for l in program.tree.getChildren():
    print str(l)+" -> "+str(l.getType())
except ParseError, e:
  print "P|"+str((e.e.token.type))+"|"
except LexerError, e:
  print "L|"+str(e.e.node)+"|"
                                              


