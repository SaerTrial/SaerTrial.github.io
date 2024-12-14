---
title: Static Program Analysis Notes
categories:
- program analysis
---

Back in the day, I was always confused about how a "professional" analysis looks like. I has indeed gained some experience of binary analysis from CTF games, such as re-constructing a control flow, and resolving a function as well as data structure somehow. Unlike program analysis, we have access to source code and origin of programming languages. A good example is that java developers usually facilitate reflection to decouple modules according to principles of software engineering. A binary file does not embody original programming logic and language features, and even a stripped binary file loses information about symbols of its project and libraries. 

Regardless of potential disagreements, I find it truly challenging to comprehand a whole program through those approaches, and struggle to effectively detect a vulnerability or bug based on acquired information. For instance, pesudo code derived from reverse engineering tools, such as ghidra and IDA, could be pretty messy and baffling, meaning that a high level of compiler optimization or obfuscation prevents pesudo code from being human-readable; moreover, resolving a function and its parameters is tedious without a symbol table, which makes it nearly impossible to perform a same level of analysis as having source code. Hence, I have been sort of fed up with doing low-level stuff without any progression or kownledge gain in analysis, and turned to static program analysis for a deep and systematic dive into theories and techniques behind "useful" analysis.

The link of this course is [here](https://tai-e.pascal-lab.net/en/lectures.html). I have uploaded my solutions of all assignments, including constant propagation and pointer analysis. They are stored in a [git repo](https://github.com/SaerTrial/static-program-analysis-assignment).

## Must and May Analysis

A lattice has greatest and lowest fixed points. Why does must analysis eventually reach to the greatest fixed point and may analysis get to the lowest one?

![Image alt]({{ site.baseurl }}/assets/image/2024-12-14-static-program-analysis/must_may_analysis.png
 "overview of must and may analysis").


This question actually comes down to propagation direction, where must analysis kicks off from the greatest element of its partial set, and vice versus. Ant analysis flows unsafe facts towards safe facts. A further question is how to identify if the greatest/lowest element holds safe or unsafe facts? I had no idea early but later realize that truthiness is a principal for judgement. When it comes to must analysis, its greatest element represents the meaning that all () must (), and the lowest one shows that none () must (). The content in brackets depends on a question that the analysis answers. From a truthiness perspective, we could feel that the meaning of the greatest element is unsafe because there maybe false positives, while that of the lowest one is too safe because many positive facts are excluded and a few of them are left. This also reflects on why we only focus on the greatest fixed point for must analysis even though there are far more fixed points.

Once we know which element is utilized as a starting point, the kind of the fixed is understood according to fixed-point theorem. If we apply a transfer function to the greatest point, then the fixed point corresponds to be greatest. Furthermore, regarding must analysis, its operator in lattice is meet (intersection), indicating that only true facts are left through propagation, thus the greatest fixed point is the upper bound.

![Image alt]({{ site.baseurl }}/assets/image/2024-12-14-static-program-analysis/fixed_point_theorem.png
 "fixed-point theorem").

Last but not least, a rule of thumb in design of a new analysis approach is soundness even though soundiness has been proposed against unrealistics introduced by soundness in practice. To guarantee soundness, the analysis approach should satisfy over-approximation, and terminate at the point where some true facts are excluded to keep found facts as true in a conservative manner. Therefore, when designing a new analysis approach, we do not just consider monotonicity of a transfer function, but apply over-approximation in the operation of the function.

