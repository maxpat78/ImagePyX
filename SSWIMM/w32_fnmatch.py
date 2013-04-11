import fnmatch
import re

COPYRIGHT = '''Copyright (C)2012, by maxpat78. GNU GPL v2 applies.'''

""" Win32 CMD command prompt (NT 3.1+) wildcards matching algorithm,
implementing the following rules (when the file system supports long names):

   1. * and *.* match all
   2. *. matches all without extension
   3. .* repeated n times matches without or with up to n extensions
   4. ? matches 1 character; 0 or 1 if followed by only wildcards
   5. * matches multiple dots; ? does not (except in NT 3.1)
   6. *.xyz (3 characters ext, even with 1-2 ??) matches any longer xyz ext
   7. [ and ] are valid name characters

According to official sources, the star should match zero or more characters,
and the question mark exactly one.

Reviewing the help for FsRtlIsNameInExpression API in NT kernel, it seems
easy to say that the command interpretr implements a mix of rules. MSDN says:

* (asterisk)            Matches zero or more characters.
? (question mark)       Matches a single character.
DOS_DOT                 Matches either a period or zero characters beyond the name string.
DOS_QM                  Matches any single character or, upon encountering a period or end of name string,
                        advances the expression to the end of the set of contiguous DOS_QMs.
DOS_STAR                Matches zero or more characters until encountering and matching the final . in the
                        name.

In the COMMAND.COM, there are different rules:

   1. * matches all file names without extension
   2. .* matches all extensions
   3. characters after a star are discarded
   4. [ and ] aren't valid in file names
   5. ? follows CMD's rule 4
   6. neither ? nor * matches multiple dots

Under Windows 9x/ME, COMMAND.COM has long file names support and follows
rules 1-2 and 5-7 like CMD; but ? matches 1 character only, except dot. """

def _all_jolly(i, s):
	"Scans a pattern to see if there are only wildcards before dot or end"
	ret = True
	while i < len(s):
		if s[i] == '.': break
		if s[i] not in "*?": ret = False
		i = i+1
	return ret

def win32_translate(wild):
	"""Translate a Win32 wildcard into a regular expression.
	Implements following rules inducted from DIR behaviour in XP+ Command Prompt:
		* is regex .* when not included in a terminating *.
		a terminating *. means "without extension" and becomes [^.]+
		? is regex [^.] if not followed by wildcards only (until end or the next dot)
		? becomes regex [^.]? if followed by wildcards only
		. followed by wildcards only alternatively matches a base name with or
		without extension, so the regex becomes base$|base\.
	"""
	i, n = 0, len(wild)
	res = ''
	while i < n:
		c = wild[i]
		if c == '*':
			if i == n-2 and wild[i+1] == '.':
				res = res + '[^.]+'
				break
			else:
				res = res + '.*'
		elif c == '?':
			res = res + '[^.]' # ? doesn't match dot
			if _all_jolly(i+1, wild):
				res = res + '?'
		elif c == '.':
			if i == n-1: break
			if _all_jolly(i+1, wild):
				res = res + '$|%s\.' % res
			else:
				res = res + '\.'
		else:
			res = res + re.escape(c)
		i = i+1
		
	# Exception: ending star with 3-chars extension matches all longer extensions
	if re.search('\*\.[^.]{3}$', wild):
	    res += '[^.]*'

	res = '^%s$(?i)' % res
	#~ print "DEBUG: Wildcard '%s' ==> Regex '%s'" % (wild, res)
	return res


__all__ = ["filter", "fnmatch", "translate"]

translate = win32_translate
fnmatch.translate = win32_translate

if __name__ == '__main__':
	cases = (
	('ab[1].c', 'ab[1].c', True), # Win32 must match, [] aren't wildcards
	('abc.d', 'AbC.d', True), # Win32 must match, file system is case-insensitive
	('ab', 'ab?', True), # 0|1 char
	('ac', 'a?c', False), # 1 char
	('abc', 'a??c', False), # 2 chars
	('abcd', 'a??c', False), # 2 chars
	('abcc', 'a??c', True), # 2 chars
	('abc', '*.', True), # no ext
	('abc.d', '*.', False),
	('abc.d', '*.*d', True), # ext ending in "d"
	('ab.cd', '*.*d', True),
	('abc', '*.*', True), # with ext or not
	('abc.d', '*.*', True),
	('abc', '*ab.*', False),
	('abc', '*abc.*', True),
	('abc', '*.?', True),
	('abc.d', '*.*', True),
	('abc.d', '*.?', True),
	('ab', 'a????', True), # a + 0-4 chars
	('abcde', 'a????', True), # a + 0-4 chars
	('ab', 'a????.??', True), # a + 0-4 chars, w/ or w/o ext of 1-2 chars
	('ab', '?a????', False),
	('ab.c', 'a????.??', True),
	('ab.cd', 'a????.??', True),
	('ab.cde', 'a????.??', False),
	('ab.c', 'ab.?', True), # w/o ext or w/ 1 char ext
	('abc', 'ab.?', False),
	('ab', 'ab.?', True),
	('ab.ca', 'ab.?a', True), # w/ 2 chars ext ending in a
	('ab', 'ab.?a', False),
	('abcdef.ghi', 'ab*.???', True),
	('abcdef.ghi', 'abc???.???', True),
	('abcdef.ghi', 'abcdef.?h?', True),
	('abcdef.ghi', 'abcdef.?g?', False),
	('abcdef.ghi', 'abcdef.*', True),
	('abcdef.ghi', '*abc*', True),
	('abcdef.ghi', '*abc*.*', True),
	('abcdef.ghi', '*abc*.*hi', True),
	('abcdef.ghi', '*abc*.*hj', False),
	('abcdef.ghi', '*f*.gh?', True),
	('ab.ca', 'ab.*', True), # any ext
	('b...txt', 'b*.txt', True), # b with anything ending in .txt
	('b...txt', 'b??.txt', False), # it seems logic, but doesn't work at the Prompt!
	('b....txt', 'b...txt', False),
	('minilj.txt', '*.ini', False),
	('abcde.fgh', 'abc*.', False),
	('abcde', 'abc*.', True),
	('abcde', 'ab*e', True),
	('abc', 'ab*e', False),
	('abc', 'abc.*', True),
	('abc.de.fgh', 'abc.*', True),
	('abc.de.fgh', 'abc.*.*', True),
	('abc.de.fgh', 'abc.??.*', True),
	('abc.fgh', 'abc.*.*', True),
	('abc.fgh', 'abc.*.', True),
	('abc.fgh', 'abc.*..', True),
	('abcfgh', 'abc.*.*', False),
	('abc.de.fgh', '*.de.f*', True),
	('abc.de.fgh', '*de.f*', True),
	('abc.de.fgh', '*f*', True),
	('abc..de...fgh', '*de*f*', True),
	('abc..de...fgh', 'abc..de.*fgh', True),
	('abc.d', '***?*', True),
	('abc.d.e', '*.e', True), # with ending .e ext
	('abc.e.ef', '*.e', False),
	('abc.e.e', '*.e', True),
	('abc.e.ef', '*.e*', True), # with .e ext
	('abc.e.e', '*.e*', True),
	('abc.e.effe', '*.e*e', True),
	('abcde.fgh', '*.fgh', True),
	('abcde.fghi', '*.fgh', True), # Prompt says TRUE!!!
	('abcde.fghi', '*.fg?', True), # And so here!
	('abcde.fghi', '*.?gh', True), # And so here!
	('abcde.fghi', '*.f??', True), # And so here!
	('abcde.fghil', 'abc??*.fgh', True), # And so here!
	('abcde.fghi', 'abc??.fgh', False), # Here Prompt works!!!
	('abcde.fghil', '*.fghi', False), # Here too...
	('abcde.fgh.fgh', '*.fgh', True),
	('abcde.fgh.fg', '*.fgh', False),
	('abcde.fg.fgh', '*.fgh', True),
	('abcde.fghabc.fghab', '*.fgh', True), # And here!
	('abcde.fg.fgh.fgho', '*.fghi', False),
	('abcde.fg.fgh.fgho', '*.fgh?', True),
		)

	failed = 0

	for case in cases:
		r = fnmatch.fnmatch(case[0], case[1])
		if r != case[2]:
			failed += 1
			print "'%s' ~= '%s' is %s, expected %s" % (case[0], case[1], r, case[2])

	if failed:
		print "%d/%d tests failed!" % (failed, len(cases))
	else:
		print "All %d tests passed!" % len(cases)
