from app.core.tokenizer import input_count


class BudgetStop(Exception):
    pass


def cost(prices, i, o, cached):
    if prices is None or None in (i, o, cached) or cached > i:
        return None
    return ((i - cached) * prices.input + cached * prices.cached + o * prices.output) / 1_000_000


class Budget:
    """Reserve synchronously on the event loop before dispatch, settle exactly once."""
    def __init__(self, spec):
        self.opts = spec.controls
        self.prices = spec.prices
        self.limit = self.opts.budget_usd or (1.0 if spec.mode == "quick" else 2.0)
        self.sent = self.tokens = self.reserved_tokens = 0
        self.charged = self.spent = self.reserved_usd = 0.
        self.unknown_cost = 0
        self.stopped = ""

    def reserve(self, body, auxiliary=False):
        i = input_count(body) if not auxiliary else 0
        o = body.get("max_output_tokens", body.get("max_completion_tokens", 0))
        tokens = i + o
        usd = (i * max(self.prices.input, self.prices.cached) + o * self.prices.output) / 1e6 if self.prices else 0.
        if not self.stopped:
            if self.prices and self.charged + self.reserved_usd + usd > self.limit:
                self.stopped = "因预算熔断提前结束，样本不完整"
            elif not self.prices and (self.sent >= self.opts.max_requests or
                                      self.tokens + self.reserved_tokens + tokens > self.opts.max_tokens):
                self.stopped = "因最大请求数或最大总 token 数物理熔断提前结束，样本不完整"
        if self.stopped:
            raise BudgetStop(self.stopped)
        self.sent += 1
        self.reserved_tokens += tokens
        self.reserved_usd += usd
        return tokens, usd

    def settle(self, reservation, row, auxiliary=False):
        tokens, usd = reservation
        self.reserved_tokens -= tokens
        self.reserved_usd -= usd
        if row is None:
            self.tokens += tokens
            self.charged += usd
            if self.prices and not auxiliary:
                self.unknown_cost += 1
            return
        c = row.counts
        i = c.get("input")
        o = c.get("output")
        reserved_output = max(0, tokens-row.local_input)
        self.tokens += (i if i is not None else row.local_input) + (o if o is not None else max(row.local_output,reserved_output))
        row.cost = 0. if auxiliary and self.prices else cost(self.prices, i, o, c.get("cached"))
        if self.prices and row.cost is None:
            self.unknown_cost += 1
        self.spent += row.cost or 0.
        self.charged += usd if row.cost is None else row.cost

    def snapshot(self):
        return {"sent": self.sent, "tokens": self.tokens, "cost": self.spent if self.prices else None,
                "unknown_cost": self.unknown_cost, "budget": self.limit, "reserved": self.reserved_tokens}
