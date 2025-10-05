<h1 align="center">
    <img align="left" width="100" height="100" src="https://zetafence.com/images/logo.png" alt="Zetafence"/>
    <br />
    <p style="color: #808080; text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.5);">
    Simulations for Privilege Access Management using NGAC
    </p>
</h1>

<br/>

## Experimental Setup

We intend to perform three sets of experiments starting with practical AWS ARNs, and generating a vastly
larger number of ARNs and associations. For each of these experiments, we rerun those starting with
a handful of users to several thousands of users, roles, and resources.

Permissions are only handful supported by AWS, but limited to the PAM usecase such as `iam:PassRole`,
`iam:UpdateAssumeRolePolicy`, `iam:AttachRolePolicy`, `s3:PutObject`, `ec2:RunInstances`, and so on.
We demonstrate privilege escalation as the primary PAM usecase in order to compare the various
approaches, but find that other usecases have similar results that are explained later.

Following are some variants of experiments we intend to perform.

- ABAC with Regular Graph DAG for PAM
- NGAC policy graph with Regular Graph DAG for PAM
- NGAC policy utilizing Hypergraph for PAM

## Graph Building Procedure: ABAC vs NGAC

We build ABAC graph by adding individual nodes, adding attributes to those nodes, and traversing
the graph nodes to edges that are resources matching those attributes.

For NGAC policy using regular graphs, we build graphs by adding users, user-attributes, resources,
resource-attributes, and policy classes. We build several layers of this policy graph at beginning,
and reuse the graph for traversals identifying PAM controls.

For NGAC policy using Hypergraphs, we build graphs by adding many nodes, and hyperedges at the
beginning. Once hyperedges are added, traversal does set-theoretic operations.

- Resources: EC2, S3, KMS, RDS
- User Type: Admin, User, Service; Auth Type: Password, MFA, Federated
- Permissions: iam, ec2, s3

## Metrics

We seek to determine and contrast the following heuristics and metrics across the various systems.

- Graph sizes (nodes + edges)
- frequency of graph updates/traversal
- detection times vs #users, roles,
- detection accuracy, precisions
- false positives vs false negatives

Among the metrics, we compare the growth complexity functions across various models, and understand
their impact.

<br/>Copyright (C)
    <a href="https://zetafence.com">
    <img align="center" width="85" src="https://img.shields.io/badge/Zetafence-8A2BE2" alt="Zetafence"/></a>
2025.
