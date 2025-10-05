import random
import time
import csv
import hypernetx as hnx

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

    # Dictionary to hold all edges
    edges = {}
    edge_count = 0

    # Register all nodes in a dictionary to be added explicitly
    nodes = set()

    ground_truth_paths = {}

    # Add user nodes and associate them with realistic permission-resource edges
    for user, data in users.items():
        nodes.add(user)
        selected_permission = random.choice(permissions)
        selected_resource = random.choice(list(resources.keys()))
        selected_policy_class = random.choice(policy_classes)

        # Link users directly to permissions and resources (Bidirectional edge addition)
        edges[f"Edge_User_{edge_count}"] = {user, selected_permission, selected_resource}
        edge_count += 1

        # Inject Ground Truth Path
        if random.random() < 0.3:  # 30% chance of creating a ground truth path
            ground_truth_paths[user] = selected_policy_class
            edges[f"Edge_Truth_{edge_count}"] = {user, selected_policy_class}
            edge_count += 1

        for key, value in data.items():
            attribute_node = f'{user}_{key}:{value}'
            nodes.add(attribute_node)
            edges[f"Edge_{edge_count}"] = {user, attribute_node}
            edge_count += 1

    # Add resource nodes
    for resource, data in resources.items():
        nodes.add(resource)
        for key, value in data.items():
            attribute_node = f'{resource}_{key}:{value}'
            nodes.add(attribute_node)
            edges[f"Edge_{edge_count}"] = {attribute_node, resource}
            edge_count += 1

    # Add permission nodes
    for permission in permissions:
        nodes.add(permission)
        for resource in resources:
            edges[f"Edge_{edge_count}"] = {permission, resource}
            edge_count += 1
        for policy_class in policy_classes:
            edges[f"Edge_{edge_count}"] = {resource, policy_class}
            edge_count += 1

    # Add policy classes as nodes
    for policy_class in policy_classes:
        nodes.add(policy_class)

    # Initialize Hypergraph with edges
    H = hnx.Hypergraph(edges)

    return users, resources, permissions, policy_classes, H, ground_truth_paths

def detect_privilege_escalation(H, ground_truth_paths):
    global traversal_count
    traversal_count = 0
    escalation_paths = {}
    path_lengths = []

    false_positives = 0
    false_negatives = 0

    for user in H.nodes:
        if 'User_' in user:
            for edge_key in H.edges:
                edge_members = H.incidence_dict.get(edge_key, set())  
                if user in edge_members:  
                    if any(member in ['IAM', 'EC2', 'S3', 'KMS', 'RDS'] for member in edge_members):
                        traversal_count += 1
                        escalation_paths[user] = edge_members
                        path_lengths.append(1)

                        if user not in ground_truth_paths:  
                            false_positives += 1

    for user, policy_class in ground_truth_paths.items():
        if user not in escalation_paths:  
            false_negatives += 1

    if len(path_lengths) > 0:
        path_complexity = sum(path_lengths) / len(path_lengths)
    else:
        path_complexity = 0

    return escalation_paths, path_complexity, traversal_count, false_positives, false_negatives

def run_ngac_hypergraph_simulation(repetitions=1):
    results = []

    log_ranges = [
        (100, 4, 40, 6, 10),
        (200, 6, 60, 8, 15),
        (400, 8, 80, 10, 20),
        (600, 10, 100, 12, 25),
        (800, 12, 120, 14, 30),
        (1000, 14, 140, 16, 35)
    ]

    for _ in range(repetitions):
        for num_users, num_user_attributes, num_resources, num_resource_attributes, num_permissions in log_ranges:

            users, resources, permissions, policy_classes, H, ground_truth_paths = generate_ngac_model(
                num_users, num_user_attributes, num_resources, num_resource_attributes, num_permissions)

            start_time = time.time()
            detected_paths, path_complexity, traversal_frequency, fp, fn = detect_privilege_escalation(H, ground_truth_paths)
            detection_time = time.time() - start_time

            detection_accuracy = len(detected_paths) / max(1, len(users))

            num_nodes = len(H.nodes)
            num_edges = len(H.edges)
            graph_size = num_nodes + num_edges  

            results.append([num_users, num_user_attributes, num_resources, num_resource_attributes, num_permissions,
                            detection_accuracy, path_complexity, traversal_frequency, detection_time, graph_size,
                            fp, fn])

    csv_file = '/tmp/ngac_hypergraph_simulation_with_fp_fn.csv'
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Num_Users', 'Num_User_Attributes', 'Num_Resources', 'Num_Resource_Attributes', 'Num_Permissions',
                         'Detection_Accuracy', 'Path_Complexity', 'Traversal_Frequency', 'Detection_Time', 'Graph_Size',
                         'False_Positives', 'False_Negatives'])
        for row in results:
            writer.writerow(row)

    return csv_file


if __name__ == "__main__":
    run_ngac_hypergraph_simulation(repetitions=1)

