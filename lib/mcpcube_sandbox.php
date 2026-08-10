<?php

declare(strict_types=1);

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;

/**
 * Hard-abort error: syntax error, a disallowed language construct, or the
 * step/time budget was exceeded. Never catchable by the script's own
 * try/catch - if the script did something the sandbox doesn't allow, the
 * whole call fails.
 */
final class mcpcube_sandbox_error extends RuntimeException
{
}

/**
 * Catchable-in-script runtime error: division by zero, a bad argument to an
 * API method, an unknown variable/object, etc. mcpcube_tool_error (thrown by
 * the API facades, e.g. "insufficient scope" or "confirmation required") is
 * caught by the same in-script try/catch, since both represent an ordinary
 * failure the script may want to react to.
 */
final class mcpcube_sandbox_runtime_error extends RuntimeException
{
}

/** Marker for the internal control-flow exceptions (return/break/continue). Never catchable in-script. */
interface mcpcube_sandbox_signal
{
}

final class mcpcube_sandbox_return_signal extends RuntimeException implements mcpcube_sandbox_signal
{
    public function __construct(public readonly mixed $value)
    {
        parent::__construct('return');
    }
}

final class mcpcube_sandbox_break_signal extends RuntimeException implements mcpcube_sandbox_signal
{
    public function __construct(public int $levels = 1)
    {
        parent::__construct('break');
    }
}

final class mcpcube_sandbox_continue_signal extends RuntimeException implements mcpcube_sandbox_signal
{
    public function __construct(public int $levels = 1)
    {
        parent::__construct('continue');
    }
}

/**
 * Pre-execution AST gate. Walks the parsed script once and rejects anything
 * outside a small, explicit allow-list of statement/expression node types
 * *before* a single line runs. In particular this always rejects: function
 * and class declarations, closures/arrow functions, `new`, plain function
 * calls (FuncCall - only MethodCall on the injected API objects is allowed),
 * static calls/property access, include/require, eval, exit, global/static
 * variables, and references. There is no escape hatch from this list; if a
 * node type isn't explicitly allowed below, the script is rejected.
 */
final class mcpcube_sandbox_validator extends NodeVisitorAbstract
{
    /** @var list<class-string> */
    private const ALLOWED_CLASSES = [
        Node\Stmt\Expression::class,
        Node\Stmt\If_::class,
        Node\Stmt\ElseIf_::class,
        Node\Stmt\Else_::class,
        Node\Stmt\Foreach_::class,
        Node\Stmt\For_::class,
        Node\Stmt\While_::class,
        Node\Stmt\Do_::class,
        Node\Stmt\Return_::class,
        Node\Stmt\Echo_::class,
        Node\Stmt\Break_::class,
        Node\Stmt\Continue_::class,
        Node\Stmt\TryCatch::class,
        Node\Stmt\Catch_::class,
        Node\Stmt\Finally_::class,
        Node\Stmt\Nop::class,
        Node\Expr\Variable::class,
        Node\Expr\Assign::class,
        Node\Expr\AssignOp\Plus::class,
        Node\Expr\AssignOp\Minus::class,
        Node\Expr\AssignOp\Mul::class,
        Node\Expr\AssignOp\Div::class,
        Node\Expr\AssignOp\Concat::class,
        Node\Expr\AssignOp\Mod::class,
        Node\Expr\AssignOp\Coalesce::class,
        Node\Expr\PreInc::class,
        Node\Expr\PostInc::class,
        Node\Expr\PreDec::class,
        Node\Expr\PostDec::class,
        Node\Expr\Array_::class,
        Node\Expr\ArrayItem::class,
        Node\Expr\ArrayDimFetch::class,
        Node\Expr\BinaryOp\Concat::class,
        Node\Expr\BinaryOp\Plus::class,
        Node\Expr\BinaryOp\Minus::class,
        Node\Expr\BinaryOp\Mul::class,
        Node\Expr\BinaryOp\Div::class,
        Node\Expr\BinaryOp\Mod::class,
        Node\Expr\BinaryOp\Pow::class,
        Node\Expr\BinaryOp\Equal::class,
        Node\Expr\BinaryOp\NotEqual::class,
        Node\Expr\BinaryOp\Identical::class,
        Node\Expr\BinaryOp\NotIdentical::class,
        Node\Expr\BinaryOp\Smaller::class,
        Node\Expr\BinaryOp\SmallerOrEqual::class,
        Node\Expr\BinaryOp\Greater::class,
        Node\Expr\BinaryOp\GreaterOrEqual::class,
        Node\Expr\BinaryOp\Spaceship::class,
        Node\Expr\BinaryOp\BooleanAnd::class,
        Node\Expr\BinaryOp\BooleanOr::class,
        Node\Expr\BinaryOp\LogicalAnd::class,
        Node\Expr\BinaryOp\LogicalOr::class,
        Node\Expr\BinaryOp\Coalesce::class,
        Node\Expr\BooleanNot::class,
        Node\Expr\UnaryMinus::class,
        Node\Expr\UnaryPlus::class,
        Node\Expr\Ternary::class,
        Node\Expr\MethodCall::class,
        Node\Expr\ConstFetch::class,
        Node\Expr\Isset_::class,
        Node\Expr\Empty_::class,
        Node\Expr\Cast\Int_::class,
        Node\Expr\Cast\String_::class,
        Node\Expr\Cast\Bool_::class,
        Node\Expr\Cast\Array_::class,
        Node\Expr\Cast\Double::class,
        Node\Scalar\String_::class,
        Node\Scalar\LNumber::class,
        Node\Scalar\DNumber::class,
        Node\Scalar\Encapsed::class,
        Node\Scalar\EncapsedStringPart::class,
        Node\Arg::class,
        Node\Identifier::class,
        Node\Name::class,
    ];

    public function enterNode(Node $node)
    {
        $class = get_class($node);

        if (!in_array($class, self::ALLOWED_CLASSES, true)) {
            throw new mcpcube_sandbox_error(sprintf(
                'Line %d: "%s" is not allowed in a script. Only variables, arrays, if/for/foreach/while/do, '
                    . 'try/catch, return/break/continue/echo, arithmetic/comparison operators, and calls to '
                    . 'methods on the provided API objects are permitted. No functions, classes, closures, `new`, '
                    . 'globals, includes, or plain function calls.',
                $node->getStartLine(),
                $node->getType()
            ));
        }

        if ($node instanceof Node\Expr\Variable && !is_string($node->name)) {
            throw new mcpcube_sandbox_error(sprintf('Line %d: variable-variables ($$x) are not allowed.', $node->getStartLine()));
        }

        if ($node instanceof Node\Expr\MethodCall && !($node->name instanceof Node\Identifier)) {
            throw new mcpcube_sandbox_error(sprintf('Line %d: dynamic method names are not allowed.', $node->getStartLine()));
        }

        if ($node instanceof Node\Expr\ConstFetch
            && !in_array(strtolower($node->name->toString()), ['true', 'false', 'null'], true)
        ) {
            throw new mcpcube_sandbox_error(sprintf(
                'Line %d: only the constants true, false, and null are allowed (found "%s").',
                $node->getStartLine(),
                $node->name->toString()
            ));
        }

        return null;
    }
}

/**
 * Tree-walking interpreter for the script-only "code mode" execute_script
 * tool. Deliberately not PHP's own eval() or a real PHP engine: every node
 * type it executes was pre-approved by mcpcube_sandbox_validator, and the
 * only way a script can affect anything outside its own local variables is
 * by calling a public method on one of the API facade objects it was handed
 * (see lib/mcpcube_api_*.php), each of which enforces its own OAuth scope
 * check against the calling agent's mcpcube_auth_context.
 */
final class mcpcube_sandbox
{
    private const MAX_STEPS = 50000;
    private const MAX_SECONDS = 10.0;

    /** @var array<string, mixed> */
    private array $vars = [];

    /** @var list<string> */
    private array $output = [];

    private int $steps = 0;

    private float $startTime;

    /** @param array<string, object> $apiObjects variable name (without $) => facade instance */
    private function __construct(private readonly array $apiObjects)
    {
        $this->startTime = microtime(true);
    }

    /**
     * @param array<string, object> $apiObjects
     * @return array{return: mixed, output: list<string>}
     */
    public static function run(string $code, array $apiObjects): array
    {
        $parser = (new ParserFactory())->create(ParserFactory::PREFER_PHP7);

        try {
            $ast = $parser->parse("<?php\n" . $code);
        } catch (PhpParser\Error $e) {
            throw new mcpcube_sandbox_error('Syntax error: ' . $e->getMessage());
        }

        if ($ast === null) {
            $ast = [];
        }

        $traverser = new PhpParser\NodeTraverser();
        $traverser->addVisitor(new mcpcube_sandbox_validator());
        $traverser->traverse($ast);

        $sandbox = new self($apiObjects);
        $returnValue = null;

        try {
            $sandbox->exec_stmts($ast);
        } catch (mcpcube_sandbox_return_signal $r) {
            $returnValue = $r->value;
        } catch (mcpcube_sandbox_signal $s) {
            throw new mcpcube_sandbox_error('break/continue used outside of a loop.');
        }

        return ['return' => $returnValue, 'output' => $sandbox->output];
    }

    // ---------------------------------------------------------------
    // Statements
    // ---------------------------------------------------------------

    /** @param Node\Stmt[] $stmts */
    private function exec_stmts(array $stmts): void
    {
        foreach ($stmts as $stmt) {
            $this->exec_stmt($stmt);
        }
    }

    private function exec_stmt(Node\Stmt $stmt): void
    {
        $this->tick();

        if ($stmt instanceof Node\Stmt\Expression) {
            $this->eval_expr($stmt->expr);
            return;
        }

        if ($stmt instanceof Node\Stmt\Nop) {
            return;
        }

        if ($stmt instanceof Node\Stmt\Echo_) {
            foreach ($stmt->exprs as $expr) {
                $this->output[] = $this->stringify($this->eval_expr($expr));
            }
            return;
        }

        if ($stmt instanceof Node\Stmt\Return_) {
            throw new mcpcube_sandbox_return_signal($stmt->expr !== null ? $this->eval_expr($stmt->expr) : null);
        }

        if ($stmt instanceof Node\Stmt\Break_) {
            throw new mcpcube_sandbox_break_signal($stmt->num !== null ? max(1, (int) $this->eval_expr($stmt->num)) : 1);
        }

        if ($stmt instanceof Node\Stmt\Continue_) {
            throw new mcpcube_sandbox_continue_signal($stmt->num !== null ? max(1, (int) $this->eval_expr($stmt->num)) : 1);
        }

        if ($stmt instanceof Node\Stmt\If_) {
            if ($this->truthy($this->eval_expr($stmt->cond))) {
                $this->exec_stmts($stmt->stmts);
                return;
            }
            foreach ($stmt->elseifs as $elseif) {
                if ($this->truthy($this->eval_expr($elseif->cond))) {
                    $this->exec_stmts($elseif->stmts);
                    return;
                }
            }
            if ($stmt->else !== null) {
                $this->exec_stmts($stmt->else->stmts);
            }
            return;
        }

        if ($stmt instanceof Node\Stmt\Foreach_) {
            $array = $this->eval_expr($stmt->expr);
            if (!is_array($array)) {
                throw new mcpcube_sandbox_runtime_error('foreach requires an array value.');
            }
            foreach ($array as $key => $value) {
                $this->tick();
                if ($stmt->keyVar !== null) {
                    $this->assign_to($stmt->keyVar, $key);
                }
                $this->assign_to($stmt->valueVar, $value);
                if (!$this->run_loop_body($stmt->stmts)) {
                    break;
                }
            }
            return;
        }

        if ($stmt instanceof Node\Stmt\While_) {
            while (true) {
                $this->tick();
                if (!$this->truthy($this->eval_expr($stmt->cond))) {
                    break;
                }
                if (!$this->run_loop_body($stmt->stmts)) {
                    break;
                }
            }
            return;
        }

        if ($stmt instanceof Node\Stmt\Do_) {
            while (true) {
                if (!$this->run_loop_body($stmt->stmts)) {
                    break;
                }
                $this->tick();
                if (!$this->truthy($this->eval_expr($stmt->cond))) {
                    break;
                }
            }
            return;
        }

        if ($stmt instanceof Node\Stmt\For_) {
            foreach ($stmt->init as $expr) {
                $this->eval_expr($expr);
            }
            while (true) {
                $this->tick();
                $continueLoop = true;
                foreach ($stmt->cond as $expr) {
                    $continueLoop = $this->truthy($this->eval_expr($expr));
                }
                if (!$continueLoop) {
                    break;
                }
                if (!$this->run_loop_body($stmt->stmts)) {
                    break;
                }
                foreach ($stmt->loop as $expr) {
                    $this->eval_expr($expr);
                }
            }
            return;
        }

        if ($stmt instanceof Node\Stmt\TryCatch) {
            try {
                try {
                    $this->exec_stmts($stmt->stmts);
                } catch (mcpcube_sandbox_signal $s) {
                    throw $s;
                } catch (mcpcube_sandbox_error $e) {
                    throw $e;
                } catch (Throwable $e) {
                    if ($stmt->catches === []) {
                        throw $e;
                    }
                    $catch = $stmt->catches[0];
                    if ($catch->var !== null && is_string($catch->var->name)) {
                        $this->vars[$catch->var->name] = ['message' => $e->getMessage()];
                    }
                    $this->exec_stmts($catch->stmts);
                }
            } finally {
                if ($stmt->finally !== null) {
                    $this->exec_stmts($stmt->finally->stmts);
                }
            }
            return;
        }

        throw new mcpcube_sandbox_error('Unsupported statement (rejected by validator, this should not happen): ' . $stmt->getType());
    }

    /** @param Node\Stmt[] $stmts @return bool false if the loop should stop (a break was hit) */
    private function run_loop_body(array $stmts): bool
    {
        try {
            $this->exec_stmts($stmts);
        } catch (mcpcube_sandbox_continue_signal $c) {
            if ($c->levels > 1) {
                $c->levels--;
                throw $c;
            }
        } catch (mcpcube_sandbox_break_signal $b) {
            if ($b->levels > 1) {
                $b->levels--;
                throw $b;
            }
            return false;
        }

        return true;
    }

    // ---------------------------------------------------------------
    // Expressions
    // ---------------------------------------------------------------

    private function eval_expr(Node\Expr $node): mixed
    {
        try {
            return $this->eval_expr_inner($node);
        } catch (TypeError|DivisionByZeroError|ArithmeticError $e) {
            throw new mcpcube_sandbox_runtime_error(sprintf('Line %d: %s', $node->getStartLine(), $e->getMessage()));
        }
    }

    private function eval_expr_inner(Node\Expr $node): mixed
    {
        if ($node instanceof Node\Expr\Variable) {
            return is_string($node->name) ? ($this->vars[$node->name] ?? null) : null;
        }

        if ($node instanceof Node\Scalar\String_) {
            return $node->value;
        }

        if ($node instanceof Node\Scalar\LNumber) {
            return $node->value;
        }

        if ($node instanceof Node\Scalar\DNumber) {
            return $node->value;
        }

        if ($node instanceof Node\Scalar\Encapsed) {
            $parts = '';
            foreach ($node->parts as $part) {
                $parts .= $part instanceof Node\Scalar\EncapsedStringPart
                    ? $part->value
                    : $this->stringify($this->eval_expr($part));
            }
            return $parts;
        }

        if ($node instanceof Node\Expr\ConstFetch) {
            return match (strtolower($node->name->toString())) {
                'true' => true,
                'false' => false,
                'null' => null,
                default => null,
            };
        }

        if ($node instanceof Node\Expr\Array_) {
            $result = [];
            foreach ($node->items as $item) {
                if ($item === null) {
                    continue;
                }
                if ($item->unpack) {
                    $spread = $this->eval_expr($item->value);
                    if (is_array($spread)) {
                        foreach ($spread as $k => $v) {
                            is_string($k) ? $result[$k] = $v : $result[] = $v;
                        }
                    }
                    continue;
                }
                $value = $this->eval_expr($item->value);
                if ($item->key !== null) {
                    $result[$this->eval_expr($item->key)] = $value;
                } else {
                    $result[] = $value;
                }
            }
            return $result;
        }

        if ($node instanceof Node\Expr\ArrayDimFetch) {
            $base = $this->eval_expr($node->var);
            if ($node->dim === null) {
                return null;
            }
            $key = $this->eval_expr($node->dim);
            if (is_array($base) && array_key_exists($key, $base)) {
                return $base[$key];
            }
            if (is_string($base) && is_int($key) && $key >= 0 && $key < strlen($base)) {
                return $base[$key];
            }
            return null;
        }

        if ($node instanceof Node\Expr\Assign) {
            $value = $this->eval_expr($node->expr);
            $this->assign_to($node->var, $value);
            return $value;
        }

        if ($node instanceof Node\Expr\AssignOp) {
            return $this->eval_assign_op($node);
        }

        if ($node instanceof Node\Expr\PreInc || $node instanceof Node\Expr\PostInc
            || $node instanceof Node\Expr\PreDec || $node instanceof Node\Expr\PostDec
        ) {
            $current = $this->eval_lvalue_current($node->var);
            $updated = ($node instanceof Node\Expr\PreInc || $node instanceof Node\Expr\PostInc)
                ? $current + 1
                : $current - 1;
            $this->assign_to($node->var, $updated);
            return ($node instanceof Node\Expr\PostInc || $node instanceof Node\Expr\PostDec) ? $current : $updated;
        }

        if ($node instanceof Node\Expr\BinaryOp\BooleanAnd || $node instanceof Node\Expr\BinaryOp\LogicalAnd) {
            return $this->truthy($this->eval_expr($node->left)) && $this->truthy($this->eval_expr($node->right));
        }

        if ($node instanceof Node\Expr\BinaryOp\BooleanOr || $node instanceof Node\Expr\BinaryOp\LogicalOr) {
            return $this->truthy($this->eval_expr($node->left)) || $this->truthy($this->eval_expr($node->right));
        }

        if ($node instanceof Node\Expr\BinaryOp\Coalesce) {
            $left = $this->eval_expr($node->left);
            return $left ?? $this->eval_expr($node->right);
        }

        if ($node instanceof Node\Expr\BinaryOp) {
            $left = $this->eval_expr($node->left);
            $right = $this->eval_expr($node->right);
            return $this->apply_binary_op($node, $left, $right);
        }

        if ($node instanceof Node\Expr\BooleanNot) {
            return !$this->truthy($this->eval_expr($node->expr));
        }

        if ($node instanceof Node\Expr\UnaryMinus) {
            return -$this->eval_expr($node->expr);
        }

        if ($node instanceof Node\Expr\UnaryPlus) {
            return +$this->eval_expr($node->expr);
        }

        if ($node instanceof Node\Expr\Ternary) {
            $cond = $this->eval_expr($node->cond);
            if ($node->if === null) {
                return $this->truthy($cond) ? $cond : $this->eval_expr($node->else);
            }
            return $this->truthy($cond) ? $this->eval_expr($node->if) : $this->eval_expr($node->else);
        }

        if ($node instanceof Node\Expr\Isset_) {
            foreach ($node->vars as $var) {
                if ($this->eval_expr($var) === null) {
                    return false;
                }
            }
            return true;
        }

        if ($node instanceof Node\Expr\Empty_) {
            return !$this->truthy($this->eval_expr($node->expr));
        }

        if ($node instanceof Node\Expr\Cast\Int_) {
            return (int) $this->eval_expr($node->expr);
        }

        if ($node instanceof Node\Expr\Cast\String_) {
            return $this->stringify($this->eval_expr($node->expr));
        }

        if ($node instanceof Node\Expr\Cast\Bool_) {
            return $this->truthy($this->eval_expr($node->expr));
        }

        if ($node instanceof Node\Expr\Cast\Array_) {
            $value = $this->eval_expr($node->expr);
            return is_array($value) ? $value : (array) $value;
        }

        if ($node instanceof Node\Expr\Cast\Double) {
            return (float) $this->eval_expr($node->expr);
        }

        if ($node instanceof Node\Expr\MethodCall) {
            return $this->eval_method_call($node);
        }

        throw new mcpcube_sandbox_error('Unsupported expression (rejected by validator, this should not happen): ' . $node->getType());
    }

    private function eval_assign_op(Node\Expr\AssignOp $node): mixed
    {
        if ($node instanceof Node\Expr\AssignOp\Coalesce) {
            $current = $this->eval_lvalue_current($node->var);
            if ($current !== null) {
                return $current;
            }
            $value = $this->eval_expr($node->expr);
            $this->assign_to($node->var, $value);
            return $value;
        }

        $current = $this->eval_lvalue_current($node->var);
        $operand = $this->eval_expr($node->expr);
        $value = match (true) {
            $node instanceof Node\Expr\AssignOp\Plus => $current + $operand,
            $node instanceof Node\Expr\AssignOp\Minus => $current - $operand,
            $node instanceof Node\Expr\AssignOp\Mul => $current * $operand,
            $node instanceof Node\Expr\AssignOp\Div => $current / $operand,
            $node instanceof Node\Expr\AssignOp\Mod => $current % $operand,
            $node instanceof Node\Expr\AssignOp\Concat => $this->stringify($current) . $this->stringify($operand),
            default => throw new mcpcube_sandbox_error('Unsupported compound assignment operator'),
        };
        $this->assign_to($node->var, $value);
        return $value;
    }

    private function eval_lvalue_current(Node\Expr $var): mixed
    {
        return $this->eval_expr($var);
    }

    private function apply_binary_op(Node\Expr\BinaryOp $node, mixed $left, mixed $right): mixed
    {
        return match (get_class($node)) {
            Node\Expr\BinaryOp\Concat::class => $this->stringify($left) . $this->stringify($right),
            Node\Expr\BinaryOp\Plus::class => $left + $right,
            Node\Expr\BinaryOp\Minus::class => $left - $right,
            Node\Expr\BinaryOp\Mul::class => $left * $right,
            Node\Expr\BinaryOp\Div::class => $left / $right,
            Node\Expr\BinaryOp\Mod::class => $left % $right,
            Node\Expr\BinaryOp\Pow::class => $left ** $right,
            Node\Expr\BinaryOp\Equal::class => $left == $right,
            Node\Expr\BinaryOp\NotEqual::class => $left != $right,
            Node\Expr\BinaryOp\Identical::class => $left === $right,
            Node\Expr\BinaryOp\NotIdentical::class => $left !== $right,
            Node\Expr\BinaryOp\Smaller::class => $left < $right,
            Node\Expr\BinaryOp\SmallerOrEqual::class => $left <= $right,
            Node\Expr\BinaryOp\Greater::class => $left > $right,
            Node\Expr\BinaryOp\GreaterOrEqual::class => $left >= $right,
            Node\Expr\BinaryOp\Spaceship::class => $left <=> $right,
            default => throw new mcpcube_sandbox_error('Unsupported binary operator: ' . $node->getType()),
        };
    }

    private function eval_method_call(Node\Expr\MethodCall $node): mixed
    {
        if (!($node->var instanceof Node\Expr\Variable) || !is_string($node->var->name)) {
            throw new mcpcube_sandbox_runtime_error('Method calls are only supported directly on the provided API objects, e.g. $mail->listFolders().');
        }

        $varName = $node->var->name;
        if (!array_key_exists($varName, $this->apiObjects)) {
            throw new mcpcube_sandbox_runtime_error(
                "Unknown object \${$varName}. Available objects: \$" . implode(', $', array_keys($this->apiObjects)) . '.'
            );
        }

        /** @var Node\Identifier $nameNode validator guarantees this */
        $nameNode = $node->name;
        $method = $nameNode->toString();
        $object = $this->apiObjects[$varName];

        if (!method_exists($object, $method)) {
            throw new mcpcube_sandbox_runtime_error("Unknown method \${$varName}->{$method}().");
        }

        $reflection = new ReflectionMethod($object, $method);
        if (!$reflection->isPublic()) {
            throw new mcpcube_sandbox_runtime_error("Unknown method \${$varName}->{$method}().");
        }

        $args = $this->bind_args($reflection, $node->args);

        try {
            return $reflection->invokeArgs($object, $args);
        } catch (mcpcube_tool_error $e) {
            // Domain errors (missing scope, not found, confirmation
            // required/invalid) are ordinary catchable failures from the
            // script's point of view.
            throw $e;
        } catch (TypeError $e) {
            throw new mcpcube_sandbox_runtime_error("Invalid arguments calling \${$varName}->{$method}(): " . $e->getMessage());
        }
    }

    /** @param Node\Arg[] $argNodes @return list<mixed> */
    private function bind_args(ReflectionMethod $reflection, array $argNodes): array
    {
        $positional = [];
        $named = [];

        foreach ($argNodes as $arg) {
            $value = $this->eval_expr($arg->value);

            if ($arg->unpack) {
                if (is_array($value)) {
                    foreach ($value as $k => $v) {
                        is_string($k) ? $named[$k] = $v : $positional[] = $v;
                    }
                }
                continue;
            }

            if ($arg->name !== null) {
                $named[$arg->name->toString()] = $value;
            } else {
                $positional[] = $value;
            }
        }

        $result = [];
        foreach ($reflection->getParameters() as $i => $param) {
            $pname = $param->getName();
            if (array_key_exists($pname, $named)) {
                $result[] = $named[$pname];
            } elseif (array_key_exists($i, $positional)) {
                $result[] = $positional[$i];
            } elseif ($param->isDefaultValueAvailable()) {
                $result[] = $param->getDefaultValue();
            } elseif ($param->allowsNull()) {
                $result[] = null;
            } else {
                throw new mcpcube_sandbox_runtime_error(
                    "Missing required argument \${$pname} for {$reflection->getDeclaringClass()->getShortName()}->{$reflection->getName()}()."
                );
            }
        }

        return $result;
    }

    private function assign_to(Node\Expr $target, mixed $value): void
    {
        if ($target instanceof Node\Expr\Variable) {
            if (!is_string($target->name)) {
                throw new mcpcube_sandbox_error('Dynamic variable names are not allowed.');
            }
            $this->vars[$target->name] = $value;
            return;
        }

        if ($target instanceof Node\Expr\ArrayDimFetch) {
            $ref = &$this->get_array_ref($target->var);
            if (!is_array($ref)) {
                $ref = [];
            }
            if ($target->dim === null) {
                $ref[] = $value;
            } else {
                $ref[$this->eval_expr($target->dim)] = $value;
            }
            return;
        }

        throw new mcpcube_sandbox_error('This kind of assignment target is not supported.');
    }

    /** @return mixed */
    private function &get_array_ref(Node\Expr $node)
    {
        if ($node instanceof Node\Expr\Variable) {
            if (!is_string($node->name)) {
                throw new mcpcube_sandbox_error('Dynamic variable names are not allowed.');
            }
            if (!array_key_exists($node->name, $this->vars)) {
                $this->vars[$node->name] = [];
            }
            return $this->vars[$node->name];
        }

        if ($node instanceof Node\Expr\ArrayDimFetch) {
            $parent = &$this->get_array_ref($node->var);
            if (!is_array($parent)) {
                $parent = [];
            }
            if ($node->dim === null) {
                $parent[] = [];
                end($parent);
                $key = key($parent);
                return $parent[$key];
            }
            $key = $this->eval_expr($node->dim);
            if (!array_key_exists($key, $parent)) {
                $parent[$key] = [];
            }
            return $parent[$key];
        }

        throw new mcpcube_sandbox_error('This kind of assignment target is not supported.');
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private function truthy(mixed $value): bool
    {
        return (bool) $value;
    }

    private function stringify(mixed $value): string
    {
        if (is_string($value)) {
            return $value;
        }
        if ($value === null) {
            return '';
        }
        if (is_bool($value)) {
            return $value ? '1' : '';
        }
        if (is_array($value)) {
            return json_encode($value, JSON_UNESCAPED_SLASHES) ?: '[]';
        }
        return (string) $value;
    }

    private function tick(): void
    {
        if (++$this->steps > self::MAX_STEPS) {
            throw new mcpcube_sandbox_error('Script exceeded the maximum of ' . self::MAX_STEPS . ' executed steps. Break the task into smaller calls.');
        }
        if (($this->steps % 200) === 0 && (microtime(true) - $this->startTime) > self::MAX_SECONDS) {
            throw new mcpcube_sandbox_error('Script exceeded its ' . self::MAX_SECONDS . 's execution time budget.');
        }
    }
}
