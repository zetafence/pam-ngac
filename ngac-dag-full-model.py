import random
import time
import csv
import networkx as nx

traversal_count = 0


def generate_ngac_model(num_users, num_user_attributes, num_resources, num_resource_attributes, num_permissions):
    all_permissions = [
        'iam:PassRole', 'ec2:RunInstances', 's3:PutObject',
        'iam:AttachRolePolicy', 'iam:UpdateRole', 'iam:UpdateAssumeRolePolicy'
    ]

    users = {f"User_{i}": {
        'UserType': random.choice(['Admin', 'User', 'Service']),
        'AuthType': random.choice(['Password', 'MFA', 'Federated'])
    } for i in range(num_users)}

    resources = {f"Resource_{i}": {
        'LeastPrivilegePolicy': random.choice(['Strict', 'Relaxed']),
        'ResourceType': random.choice(['EC2', 'S3', 'KMS', 'RDS']),
        'IsCreateModify': random.choice(['True', 'False'])
    } for i in range(num_resources)}

    permissions = random.choices(all_permissions, k=num_permissions)

    policy_classes = ['IAM', 'EC2', 'S3', 'KMS', 'RDS']

    G = nx.DiGraph()

    # Add Users, Resources, User-Attributes, Resource-Attributes, Permissions, and Policy Classes to Graph
    for user, data in users.items():
        G.add_node(user, type='User')
        for key, value in data.items():
            attribute_node = f'{key}:{value}'
            G.add_node(attribute_node, type='UserAttribute')
            G.add_edge(user, attribute_node)

    for resource, data in resources.items():
        G.add_node(resource, type='Resource')
        for key, value in data.items():
            attribute_node = f'{key}:{value}'
            G.add_node(attribute_node, type='ResourceAttribute')
            G.add_edge(attribute_node, resource)

    for permission in permissions:
        G.add_node(permission, type='Permission')

    for policy_class in policy_classes:
        G.add_node(policy_class, type='PolicyClass')

    return users, resources, permissions, policy_classes, G

def build_ngac_policy_dag(G, users, resources, permissions, policy_classes):
    global traversal_count

    for user in users:
        for permission in permissions:
            G.add_edge(user, permission)

    for resource in resources:
        for permission in permissions:
            G.add_edge(permission, resource)

    for policy_class in policy_classes:
        for resource in resources:
            G.add_edge(resource, policy_class)

    return G

def detect_privilege_escalation(G):
    global traversal_count
    traversal_count = 0
    escalation_paths = {}
    path_lengths = []

    for user in [n for n, d in G.nodes(data=True) if d['type'] == 'User']:
        for successor in nx.descendants(G, user):
            if G.nodes[successor]['type'] == 'PolicyClass':
                traversal_count += 1
                escalation_paths[user] = successor
                path_lengths.append(nx.shortest_path_length(G, user, successor))

    if len(path_lengths) > 0:
        path_complexity = sum(path_lengths) / len(path_lengths)
    else:
        path_complexity = 0

    return escalation_paths, path_complexity, traversal_count

def run_ngac_simulation(log_ranges, repetitions=10):
    results = []

    for _ in range(repetitions):
        for num_users, num_user_attributes, num_resources, num_resource_attributes, num_permissions in log_ranges:

            start_time = time.time()
            users, resources, permissions, policy_classes, G = generate_ngac_model(
                num_users, num_user_attributes, num_resources, num_resource_attributes, num_permissions)
            build_time = time.time() - start_time

            G = build_ngac_policy_dag(G, users, resources, permissions, policy_classes)

            start_time = time.time()
            detected_paths, path_complexity, traversal_frequency = detect_privilege_escalation(G)
            detection_time = time.time() - start_time

            detection_accuracy = len(detected_paths) / max(1, len(users))
            graph_size = G.number_of_nodes() + G.number_of_edges()

            results.append([num_users, num_user_attributes, num_resources, num_resource_attributes, num_permissions,
                            detection_accuracy, path_complexity, traversal_frequency, detection_time, graph_size, build_time])

    csv_file = '/tmp/ngac_policy_dag_full_model_results.csv'
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Num_Users', 'Num_User_Attributes', 'Num_Resources', 'Num_Resource_Attributes', 'Num_Permissions',
                         'Detection_Accuracy', 'Path_Complexity', 'Traversal_Frequency', 'Detection_Time', 'Graph_Size', 'Graph_Build_Time'])
        for row in results:
            writer.writerow(row)

    return csv_file


if __name__ == "__main__":
    log_ranges = [
        (100, 20, 30, 30, 6),
        (200, 40, 60, 60, 6),
        (400, 80, 120, 120, 6),
        (600, 100, 140, 140, 6),
        (800, 160, 240, 240, 6),
        (1000, 200, 300, 300, 6),
        (2000, 400, 600, 600, 6),
    ]
    run_ngac_simulation(log_ranges, repetitions=10)
