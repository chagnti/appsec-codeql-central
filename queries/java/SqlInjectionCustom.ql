/**
 * @name Custom: SQL injection via string concatenation
 * @description Detects SQL queries built by concatenating HTTP request parameters
 *              directly into a query string — no prepared statement used.
 * @kind problem
 * @problem.severity error
 * @id java/custom-sql-injection
 * @tags security correctness custom
 */
import java

class GetParameterCall extends MethodAccess {
  GetParameterCall() {
    this.getMethod().getName() = "getParameter" and
    this.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
  }
}

class ExecuteQueryCall extends MethodAccess {
  ExecuteQueryCall() {
    this.getMethod().getName().matches("execute%") and
    this.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("java.sql", "Statement")
  }
}

predicate containsGetParameter(Expr e) {
  e instanceof GetParameterCall
  or
  containsGetParameter(e.(AddExpr).getLeftOperand())
  or
  containsGetParameter(e.(AddExpr).getRightOperand())
  or
  // catch multi-step: q = "SELECT"; q += user; executeQuery(q)
  // prevents devs splitting concatenation across lines to dodge detection
  exists(Variable v, AssignExpr assign |
    assign.getDest() = v.getAnAccess() and
    containsGetParameter(assign.getRhs()) and
    e = v.getAnAccess()
  )
}

from ExecuteQueryCall exec
where containsGetParameter(exec.getArgument(0))
select exec, "SQL query built from HTTP request parameter — use PreparedStatement instead."
