# egk mixnet

Preliminary explorations of mixnet implementations to be used with the electionguard-kotlin library.

#### ElectionGuard Group

see [1]

- $ \Z = \{. . . , −3, −2, −1, 0, 1, 2, 3, . . . \} $ is the set of integers.

- $ \Z_n  = \{0, 1, 2, . . . , n − 1\} $ is the ring of integers modulo n.
- $ \Z_n^* $ is the multiplicative subgroup of $ \Z_n$ that consists of all invertible elements modulo n. When p is a prime,  $ \Z_p^* = \{1, 2, 3, . . . , p − 1\} $
-  $ \Z_p^r $ is the set of r-th-residues in $\Z_p^* $ . Formally, $ \Z_p^r = \{y \in \Z_p^* $ for which there exists $x \in \Z_p^*$ where $y = x^r$ mod p}. When p is a prime for which p − 1 = q * r with q a prime that is not a divisor of the integer r, then  $\Z_p^r$ is an order-q cyclic subgroup of $\Z_p^*$ , and for any $y \in \Z_p^* $ , $y \in \Z_p^r $ if and only if $y^q$ mod p = 1.


####  ElGamal exponential Encryption and Reencryption

$$
\begin{align}
(1) \\
    Encr(m, \xi) = (g^{\xi}, K^{m+\xi}) = (a, b) \\
    Encr(0, \xi') = (g^{\xi'}, K^{\xi'}) \\
    \\
(2)    \\
    (a, b)*(a',b') = (a*a', b*b') \\
    Encr(m, \xi) * Encr(m', \xi') = (g^{\xi+\xi'}, K^{m+m'+\xi+\xi'}) = Encr(m+m', \xi+\xi')\\
    \\
(3)    \\
    (a, b)^k = (a^k, b^k) \\
    Encr(m, \xi)^k = (g^{\xi*k}, K^{(m*k+\xi*k)}) = Encr(m*k, \xi*k) \\
    \\
(4)   \\
    \prod_{j=1}^n Encr(m_j, \xi_j) = (g^{\sum_{j=1}^n \xi_j}, K^{\sum_{j=1}^n m_j+ \sum_{j=1}^n \xi_j})
    = Encr(\sum_{j=1}^n m_j,\sum_{j=1}^n \xi_j) \\
    \prod_{j=1}^n Encr(m_j, \xi_j)^{k_j} = Encr(\sum_{j=1}^n (m_j*k_j),\sum_{j=1}^n (\xi_j*k_j)) \\
    \\
(5)     \\
    ReEncr(m, r) = (g^{\xi+r}, K^{m+\xi+r}) = Encr(0, r) * Encr(m, \xi) \\
    ReEncr(m, r)^k = Encr(0, r*k) * Encr(m*k, \xi*k) \\
    \\
(6)    \\
    \prod_{j=1}^n ReEncr(m_j, r_j)^{k_j} = \prod_{j=1}^n Encr(0, r_j*k_j) * \prod_{j=1}^n Encr(m_j*k_j, \xi_j*k_j) \\
    = Encr(0,\sum_{j=1}^n (r_j*k_j)) * \prod_{j=1}^n Encr(m_j, \xi_j)^{k_j} \\
\end{align}
$$

Let 

- ​	$e_j = Encr(m_j, \xi_j)$ 
- ​	$mix_j = ReEncr(m_j,r_j) = ReEncr(e_j,r_j)$
- ​	$sumrk = \sum_{j=1}^n (r_j*k_j)$

Then
$$
\prod_{j=1}^n mix_j^{k_j} = Encr(0,sumrk) * \prod_{j=1}^n e_j^{k_j} \\
$$



#### TW Algorithm

Generally we will use **px** to mean the permutation of a vector **x**, **px** = $\psi(\textbf x)$, so that $x_i$ = $px_j$, where $i={\psi(j)}$ and $j={\psi^{-1}(i)}$. 

Let $\textbf m$ be a set of messages and $\textbf e$ be their encryptions **e** = Encr($\textbf m$). Let shuffle(**e**) be the mixing of $\textbf e$, consisting of a permutation $\psi$ and reencryptions ReEncr($\textbf e, \textbf r$), , where $\textbf r$ are the reencryption nonces. After the shuffle, we have **e, pe, r, pr** and $\psi$, where **pe** is the permutation of **e** and **pr** the permutation of **r**. 

Let **u** be arbitrary $\in \Z_q$ (to be specified later) and **pu** its permutation.

If the mixing is valid, then we know from above that


$$
\prod_{j=1}^n (pe_j)^{pu_j} = Encr(0,sumru) * \prod_{j=1}^n e_j^{pu_j} \\
$$
where $sumru = \sum_{j=1}^n (pr_j*pu_j)$.

However, $e_j^{pu_j} = e_i^{u_i}$ for some i, so $\prod_{j=1}^n e_j^{pu_j} = \prod_{i=1}^n e_i^{u_j}$, so we have **condition 4**:
$$
\prod_{j=1}^n (pe_j)^{pu_j} = Encr(0,sumru) * \prod_{i=1}^n e_i^{u_i} \\
$$

Note that (5.5) and line 141 of the code in *GenShuffleProof*() in [2] has
$$
Encr(1,\tilde r),\ where\ \tilde r  = \sum_{j=1}^n pr_j * u_j
$$
whereas we have
$$
Encr(0,\tilde r),\ where\ \tilde r  = \sum_{j=1}^n pr_j * pu_j
$$

The $Encr(0, ..)$ is because we use exponential ElGamal, so is fine. The use of $u_j$ instead of $pu_j$ appears to be a mistake.









##### extra stuff not needed

$$
\begin{align}
\prod_{j=1}^n ({pe}_j)^{{pu}_j} = 
\prod_{j=1}^n {ReEncr(e_j,{pr}_j)^{pu_j}} \\
= \prod_{j=1}^n {ReEncr(e_j^{pu_j},{pr}_j*pu_j}) \\
= ReEncr(\prod_{j=1}^n {e_j^{pu_j},\sum_{j=1}^n {pr}_j*pu_j}\ ) \\
= Encr(0, ru) * \prod_{j=1}^n {e_j^{pu_j}} \\
for\ ru = \sum_{j=1}^n {pr}_j*pu_j
\\
\\


\\
= ReEncr(m, \xi') = Encr(0, \xi') * Encr(m, \xi) \\
= Encr(\prod_{j=1}^n {e_j^{u_j},\sum_{j=1}^n {pr}_j*u_j}\ ) \\
where \\
 ru = \sum_{j=1}^n {pr}_j*u_j
\end{align}
$$


#### Pedersen Commitments
For a set of messages $\textbf m = (m_1 .. m_n) \in \Zeta_q$, the *Pedersen committment* to $\textbf m$ is
$$
\begin{align}
Commit(\textbf m, r) = g^{r} * h_1^{m_1} * h_2^{m_2} * .. h_n^{m_n} 
= g^{r} * \prod_{i=1}^n h_i^{m_i}
\end{align}
$$
where ($ g, \textbf h $) are generators of  $ \Z_p^r $ with randomization nonce $ r \in Z_q $.

A *permutation* $\psi : \{1, . . . , n\} \to \{1, . . . , n\} $ has a *permutation matrix* $B_\psi$ , where $b_{ij}$ = 1 if $\psi(i)$ = j, otherwise 0. If $\textbf b_i$ is the $i^{th}$ column of $B_\psi$, then the *permutation commitment* to $\psi$ is
$$
\begin{align}
    Commit(\psi, \textbf r) & = (Commit(\textbf b_1, r_1), Commit(\textbf b_2, r_2),..Commit(\textbf b_N, r_N)) \\
    where\ Commit(\textbf b_j, r_j) & = g^{r_j} * h_i ,\ for\ i=ψ^{-1}(j)
\end{align}
$$
*   Note: this differs from Verificatum implementation which seems to have
$$
\begin{align}
	Commit(\textbf b_j, r_j) & = g^{r_j} * h_j 
\end{align}
$$



#### Multitext mixing
Most of the literature assumes that each row to be mixed consists of a single ElGamalCiphertext. In our application we need the possibility that each row consists of ***width*** number of ElGamalCiphertexts:
```
data class MultiText(val ciphertexts: List<ElGamalCiphertext>)
```
The changes needed to the standard algorithms are modest:

1) In algorithms 8.4, 8.5 of [2], the challenge includes a list of all the ciphertexts and their reencryptions in their hash function:

$$
\textbf u = Hash(..., \textbf e, \textbf {pe}, pcommit, pkq, i, ...)
$$
​	Here we just flatten the list of lists of ciphertexts for $\textbf e, \textbf {pe}$. This is used in both the proof construction and the proof verification.

2. In condition 4, we have $sumru = \sum_{j=1}^n (pr_j*pu_j)$. We need to modify this to 
   $$
   sumru = \sum_{j=1}^n width * (pr_j*pu_j)
   $$
   since each $e_j$ has *width* ciphertexts, and all have $pu_j$ applied. 

Further research is needed to see if the restriction that all MultiText must have same width could be relaxed, or if unique $pu_j$ could be used within a MultText.



### References

1. Josh Benaloh and Michael Naehrig, *ElectionGuard Design Specification, Version 2.0.0*, Microsoft Research, August 18, 2023, https://github.com/microsoft/electionguard/releases/download/v2.0/EG_Spec_2_0.pdf 
2. Rolf Haenni, Reto E. Koenig, Philipp Locher, Eric Dubuis. *CHVote Protocol Specification Version 3.5*, Bern University of Applied Sciences, February 28th, 2023, https://eprint.iacr.org/2017/325.pdf
3. R. Haenni, P. Locher, R. E. Koenig, and E. Dubuis. *Pseudo-code algorithms for verifi-*
   *able re-encryption mix-nets*. In M. Brenner, K. Rohloff, J. Bonneau, A. Miller, P. Y. A.
   Ryan, V. Teague, A. Bracciali, M. Sala, F. Pintore, and M. Jakobsson, editors, FC’17,
   21st International Conference on Financial Cryptography, LNCS 10323, pages 370–384,
   Silema, Malta, 2017.
4. B. Terelius and D. Wikström. *Proofs of restricted shuffles*, In D. J. Bernstein and
   T. Lange, editors, AFRICACRYPT’10, 3rd International Conference on Cryptology in
   Africa, LNCS 6055, pages 100–113, Stellenbosch, South Africa, 2010.
5. D. Wikström. *A commitment-consistent proof of a shuffle.* In C. Boyd and J. González
   Nieto, editors, ACISP’09, 14th Australasian Conference on Information Security and
   Privacy, LNCS 5594, pages 407–421, Brisbane, Australia, 2009.
6. D. Wikström. *How to Implement a Stand-alone Verifier for the Verificatum Mix-Net VMN Version 3.1.0*, 2022-09-10, https://www.verificatum.org/files/vmnv-3.1.0.pdf