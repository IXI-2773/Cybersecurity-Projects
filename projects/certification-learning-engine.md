# Certification Learning Engines

**Don Lopez - Independent Python desktop study software - Public source**

The Security+ and SC-900 learning engines combine practice questions with answer
feedback, learner progress, adaptive review, and resumable sessions. They are
independent study projects, not official CompTIA or Microsoft products.

## The problem

A random question list does not preserve an unfinished session or explain what
a learner should revisit. The applications bring practice, explanations,
confidence tracking, and saved learner state into one Windows desktop workflow.

## Engineering work

- Practice, exam-style sessions, and adaptive Smart Practice.
- Progress persistence, session resume, backups and recovery mechanisms.
- Question-quality validation and issue-reporting tools.
- Regression checks, smoke checks, and Windows packaging workflows.

## Two concrete engineering examples

**Adaptive review:** the SC-900 tests check a 72-hour exact-item spacing rule.
An item seen just under 72 hours ago is excluded from normal eligibility while
an eligible alternative is available; exactly at 72 hours it becomes eligible.
Selection also balances review roles rather than filling a set with one kind
of question.

**Session continuity:** a test reorders two questions, then confirms that a
saved answer remains with the same canonical question ID. Other checks reject
changed bank content and quarantine an unverifiable legacy session. This avoids
attaching saved learner state to the wrong material.

## Runtime evidence and limits

The real SC-900 interface was captured on Linux/Tk using five original portfolio
example questions and no learner history. All 49 focused SC-900 checks passed,
including the named selection, spacing and session modules. Five focused
Security+ checks also passed locally. Exact revisions, screenshot hash, test
scope and the successful run are in the
[evidence record](https://github.com/IXI-2773/Cybersecurity_Portfolio/blob/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/docs/LEARNING_ENGINE_EVIDENCE_2026-10-24.md).

This does not establish Windows executable behavior or measured improvement in
exam performance. Readiness indicators are study heuristics and do not guarantee
a certification pass. The portfolio browser workbench is a separate teaching
demonstration.

## Public sources reviewed October 24, 2026

- [Security+ learning engine](https://github.com/IXI-2773/Comptia-SY0-701-Test-Learning-Engine)
- [SC-900 learning engine](https://github.com/IXI-2773/Microsoft_SC-900_Test_Learning_Engine)

[Read the visual case study](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/certification-learning-engine.html)

## Academic foundation

Completed coursework: IST 4320 Advanced Application Development and the IST 5930 Coding seminar (Fall 2024), alongside database and analytics coursework.

[Explore the academic background](https://ixi-2773.github.io/Cybersecurity_Portfolio/education.html).
