#!/usr/bin/env python3
# shamir_secret.py

import random
class ShamirSecret:
    def __init__(self, **kwargs) -> None:
        """
        Construct a ShamirSecret object.

        Parameters
        ----------
        kwargs: dict
            Contains the mandatory keyword arguments:
            secret: int
                The secret to be shared
            shares: int
                Number of shares to be generated
            threshold: int
                Minimum number of shares required to reconstruct the secret

        Example
        -------
        >>> s = ShamirSecret(secret=1234, shares=4, threshold=2)

        """
        self.secret = kwargs.get('secret')
        self.shares = kwargs.get('shares')
        self.threshold = kwargs.get('threshold')
        self.generated_shares = list()

    def __str__(self) -> str:
        return f'ShamirSecret(secret={self.secret}, shares={self.shares}, threshold={self.threshold})'

    def generate_shares(self):
        # random coefficients of the polynomial
        coefficients = tuple(random.randrange(1, self.secret // 2) for _ in range(self.threshold - 1))

        def construct_poly(s, k, a, x):
            # f(x) = a0 + a1 * x + a2 * (x ^ 2) + .... + a(k-1) * (x ^ k-1)
            # constructing the polynomial for each value of x,
            # with s as a0 and other coefficients in tuple a
            f = s
            for i, pw in zip(a, tuple(range(1, k))):
                f += i * x ** pw

            return f

        for x in range(1, self.shares + 1):
            fx = construct_poly(self.secret, self.threshold, coefficients, x)
            self.generated_shares.append((x, fx))

    def get_shares(self):
        return self.generate_shares

    def random_shares(self):
        return tuple(random.sample(self.generated_shares, k=self.threshold))

    def reconstruct(self, rand_shares) -> int:
        l = len(rand_shares)  # length: number of random shares
        x_s = tuple(map(lambda x: x[0], rand_shares))  # x values of shares
        y_s = tuple(map(lambda x: x[1], rand_shares))  # y values of shares

        def PI(vars):  # product of inputs (PI)
            acc = 1
            for v in vars:
                acc *= v

            return acc

        nume = tuple()
        deno = tuple()
        for j in range(l):
            nume += (PI(x_s[m] for m in range(l) if m != j), )
            deno += (PI(x_s[m] - x_s[j] for m in range(l) if m != j), )

        sigma = round(sum(y_s[i] * nume[i] / deno[i] for i in range(l)))

        return sigma


if __name__ == '__main__':
    s = ShamirSecret(secret=1234, shares=4, threshold=2)
    print(s)
    s.generate_shares()
    print('\nShares:', *s.get_shares(), sep='\n')
    print('\nReconstructed Secret:', s.reconstruct(s.random_shares()))
