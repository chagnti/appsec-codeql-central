/**
 * @name Custom: hardcoded password or secret in string literal
 * @description Flags string assignments to variables named password/secret/token/key
 *              that contain a non-empty literal value — likely a hardcoded credential.
 * @kind problem
 * @problem.severity error
 * @id java/custom-hardcoded-secret
 * @tags security custom
 */
import java

from Variable v, StringLiteral s, Expr init
where
  v.getName().toLowerCase().regexpMatch(".*(password|secret|token|apikey|api_key|passwd|pwd).*") and
  init = v.getAnAccess().(AssignExpr).getRhs() and
  init = s and
  s.getValue().length() > 0 and
  not s.getValue() = "" and
  not s.getValue().matches("%\\$\\{%")   // exclude property placeholders like ${db.password}
select s, "Possible hardcoded secret assigned to variable '" + v.getName() + "'."
