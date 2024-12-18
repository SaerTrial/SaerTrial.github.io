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


This question actually comes down to propagation direction, where must analysis kicks off from the greatest element of its partial set, and vice versus. Ant analysis flows unsafe facts towards safe facts. A further question is how to identify if the greatest/lowest element holds safe or unsafe facts? I had no idea early but later realize that truthiness is a principal for judgement. When it comes to must analysis, its greatest element represents the meaning that all () must (), and the lowest one shows that none () must (). The content in brackets depends on a question that the analysis answers. From a truthiness perspective, we could kind of feel that the meaning of the greatest element is unsafe because there may be false positives, while that of the lowest one is too safe because many positive facts are excluded and a few of them are left. In order words, the judgement behind "none () must ()" is safe without including any wrong results, but useless. So, we do not want to see our analysis reach there. This also reflects on why we only focus on the greatest fixed point for must analysis even though there are other fixed points available as well.

Once we know which element is utilized as a starting point, the kind of the fixed is understood according to fixed-point theorem. If we apply a transfer function to the greatest point, then the fixed point corresponds to be greatest. Furthermore, regarding must analysis, its operator in lattice is meet (intersection), indicating that only true facts are left through propagation, thus the greatest fixed point is the lower bound.

![Image alt]({{ site.baseurl }}/assets/image/2024-12-14-static-program-analysis/fixed_point_theorem.png
 "fixed-point theorem").

Last but not least, a rule of thumb in design of a new analysis approach is soundness even though soundiness has been proposed against unrealistics introduced by soundness in practice. To guarantee soundness, the analysis approach should satisfy over-approximation, and terminate at the point where some true facts are excluded to keep found facts as true in a conservative manner. Therefore, when designing a new analysis approach, we do not just consider monotonicity of a transfer function, but apply over-approximation in the operation of the function.

### Upper and Lower bound

I usually find it difficult to memorize which operation in a partial order set (meet or join) derives a lower or upper bound. Once I have found a figure in slides, I sort of figure out elements in the high position carrying more facts, while those in the low position with less facts.

Basically, when a meet operation is implemented on two elements, data facts of those two will be aggregated in another element that dominates those two in partial order. Hence, when people place this dominant element in the high position, the upper bound is naturally named this way.

![Image alt]({{ site.baseurl }}/assets/image/2024-12-14-static-program-analysis/upper_lower_bound.png
 "a good figure for understanding upper and lower bounds").


## Constant Propagation

At the moment when I am writing down here, I look back constant propagation and fail in figuring out the meaning of top and bottom elements. Since it belongs to must analysis, as of my understanding, the bottom element should represent that none of variable must hold a constant, which sounds unsafe but is wrong. Is there anything or information I miss out on? So, I review its question - "given a variable x at program point p, determine whether x holds a constant at p?", and then realize that variables need to be defined and initialized before hold a constant. "all vars must hold a constant" could be reduced to a more unsafe level, meaning that all vars are undefined and uninitialized at any program point, and this statement is reflected on the top element. In regards to the bottom one, "none of var must hold a constant" is safe by not counting any wrong judgement in but useless. Therefore, its lattice preview is like a diamond, which indicates that a defined and initialized variable is able to hold a constant.

![Image alt]({{ site.baseurl }}/assets/image/2024-12-14-static-program-analysis/constant_propagation.png
 "lattice preview of constant propagation").

Constant propagation is considered as crucial and takes up three assignments throughout this course. Especially, the previous assignment is a foundation to the later one, which is well-organized. The first one is a simple one, where students implement it against its algorithm in slides; the second one is more complicated and requires students to implement interprocedural constant propagation, where transition of data facts to a method call needs to be considered; the third one is pretty interesting and more practical, where students are asked to deal with instance field access, array access, and static field access using alias analysis, which works out by using pointer analysis results. 

Its application could be compiler optimization, or deal loop detection, etc.

## Pointer Analysis

Pointer analysis is a fundamental analyse. This course asks students to implement 
context-insensitive model, and context-sensitive one. Both of them utilize a flow-insensitive approach, and this eases difficulty of development and represents a clear application logic. The key of this approach is to assume each part of logic has no idea about how other parts are going on, and needs to deal with all cases. For example, when a method is called, it needs to be added in a call graph and connects edges between arguments and its parameters in pointer flow graph, such that a data fact could flow through at some points.

When it comes to context sensitivity, there are three approaches to maintain a context, including callsite, object creation, and type (caller class). The most attractive comparison appears between type and object approaches. Type stands out in terms of performance and effectiveness, it has less call graph edges than object approaches though. More call graph edges are found, more precise this analyse is. Precision has a profound impact on analyses built in pointer analysis, such as alias analysis and tain analysis.

## Taint analysis

Taint analysis shares similar ideas of pointer analysis. That is to say that tainted objects are liquid and flow through pointer flow graph. Additionally, we need to configure source functions, sink functions, and taint transfer in a configuration file. whenever a source function is invoked, a taint object will be created and added into a corresponding var or a field. Taint transfer is better dealt with whenever a new object propagates and a method is called.

## Abstract Interpretation

This concept is not intruduced throughout this course, while I intentionally like to complete the learning of static program analysis thoroughly and turn to look into abstract interpretation in other materials. 

Basically, abstract interpretation aims at removing reduntdant elements of a newly designed analyse relative in the choice of lattice. There are abstract and concrete domains, both of which are complete lattices. abtraction refers to a transition from the a concrete domain to abstract one by a function called abstraction functions, and the flip side is called concretization functions. It is a moment to introduce `Galois` connection, which holds when these two types of function are monotone and two properties are satisfied:

![Image alt]({{ site.baseurl }}/assets/image/2024-12-14-static-program-analysis/Galois_connection.png
 "lattice preview of constant propagation").

Essentially, the first property related to "extensive" over-approximates a concretization transition over an element in an abstract domain, 
which results in a concretized element dominating an original element that has been abstracted in the partial order. 
In a bigger picture, this property compensates missed-out elements accoring to the abstract sementics. 
When it comes to the second property, that gives the most precise possible abstract 
description description for any element in the semantic lattice, which is precise than its starting element during this transition.

![Image alt]({{ site.baseurl }}/assets/image/2024-12-14-static-program-analysis/Galois_two_properties.png
 "two properties of Galois connection in the form of diagram").

Regarding the top diagram in the figure, the finally concretized element is higher than `l`, and dominates in the partial order, indicating an extension in lattice. For the bottom one, `m` dominates the final element, meaning that a reduction is applied in the lattice and the below element is more precise. Essentially, a concrete domain has infinite objects, some of which represent a program property, and what abstract interpretation does is to look for a upper bound that includes those objects and sees the same property, such that we could prove from the point. Otherwise, the only way to prove this property is to enumerate those infinite objects, which is impossible.





