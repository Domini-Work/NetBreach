#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define MAX_NODES 50
#define INF 999999

typedef struct {
    int active;
    char name[32];
} Node;

typedef struct {
    Node nodes[MAX_NODES];
    int edges[MAX_NODES][MAX_NODES];
} Graph;

void init_graph(Graph *g) {
    for (int i = 0; i < MAX_NODES; i++) {
        g->nodes[i].active = 0;
        for (int j = 0; j < MAX_NODES; j++) {
            g->edges[i][j] = 0;
        }
    }
}

int auth_admin() {
    char pwd[32];
    printf("Enter Admin Password: ");
    scanf("%31s", pwd);
    if (strcmp(pwd, "1234") == 0) {
        return 1;
    }
    printf("Access Denied.\n");
    return 0;
}

void add_asset(Graph *g) {
    if (!auth_admin()) return;
    for (int i = 0; i < MAX_NODES; i++) {
        if (!g->nodes[i].active) {
            g->nodes[i].active = 1;
            printf("Enter Asset Name: ");
            scanf("%31s", g->nodes[i].name);
            printf("Asset %d (%s) added.\n", i, g->nodes[i].name);
            return;
        }
    }
    printf("Graph full.\n");
}

void add_vulnerability(Graph *g) {
    if (!auth_admin()) return;
    int src, dest, weight;
    printf("Enter Source Asset ID: ");
    scanf("%d", &src);
    printf("Enter Destination Asset ID: ");
    scanf("%d", &dest);
    printf("Enter Attack Difficulty (Weight): ");
    scanf("%d", &weight);

    if (src >= 0 && src < MAX_NODES && dest >= 0 && dest < MAX_NODES && 
        g->nodes[src].active && g->nodes[dest].active) {
        g->edges[src][dest] = weight;
        printf("Vulnerability added from %d to %d with difficulty %d.\n", src, dest, weight);
    } else {
        printf("Invalid asset IDs.\n");
    }
}

void remove_asset(Graph *g) {
    if (!auth_admin()) return;
    int id;
    printf("Enter Asset ID to remove: ");
    scanf("%d", &id);
    if (id >= 0 && id < MAX_NODES && g->nodes[id].active) {
        g->nodes[id].active = 0;
        for (int i = 0; i < MAX_NODES; i++) {
            g->edges[id][i] = 0;
            g->edges[i][id] = 0;
        }
        printf("Asset %d removed.\n", id);
    } else {
        printf("Invalid asset ID.\n");
    }
}

void print_network(Graph *g) {
    printf("--- Network Topology ---\n");
    for (int i = 0; i < MAX_NODES; i++) {
        if (g->nodes[i].active) {
            printf("Asset %d: %s\n", i, g->nodes[i].name);
            for (int j = 0; j < MAX_NODES; j++) {
                if (g->nodes[j].active && g->edges[i][j] > 0) {
                    printf("  -> %d (%s) [Difficulty: %d]\n", j, g->nodes[j].name, g->edges[i][j]);
                }
            }
        }
    }
}

void print_tree_node(Graph *g, int node, int parent_arr[], int is_last[], int level) {
    for (int i = 0; i < level - 1; i++) {
        if (is_last[i]) {
            printf("    ");
        } else {
            printf("\xE2\x94\x82   ");
        }
    }
    if (level > 0) {
        if (is_last[level - 1]) {
            printf("\xE2\x94\x94\xE2\x94\x80\xE2\x94\x80 ");
        } else {
            printf("\xE2\x94\x9C\xE2\x94\x80\xE2\x94\x80 ");
        }
    }
    printf("%s\n", g->nodes[node].name);

    int children[MAX_NODES];
    int child_count = 0;
    for (int i = 0; i < MAX_NODES; i++) {
        if (parent_arr[i] == node && i != node) {
            children[child_count++] = i;
        }
    }
    for (int i = 0; i < child_count; i++) {
        is_last[level] = (i == child_count - 1);
        print_tree_node(g, children[i], parent_arr, is_last, level + 1);
    }
}

void calc_blast_radius(Graph *g) {
    int start;
    printf("Enter compromised Asset ID for Blast Radius: ");
    scanf("%d", &start);
    
    if (start < 0 || start >= MAX_NODES || !g->nodes[start].active) {
        printf("Invalid asset ID.\n");
        return;
    }

    int visited[MAX_NODES] = {0};
    int queue[MAX_NODES];
    int front = 0, rear = 0;
    int parent[MAX_NODES];
    for (int i = 0; i < MAX_NODES; i++) parent[i] = -1;

    queue[rear++] = start;
    visited[start] = 1;
    parent[start] = start;

    while (front < rear) {
        int u = queue[front++];
        for (int v = 0; v < MAX_NODES; v++) {
            if (g->nodes[v].active && g->edges[u][v] > 0 && !visited[v]) {
                visited[v] = 1;
                parent[v] = u;
                queue[rear++] = v;
            }
        }
    }

    printf("--- Blast Radius Tree ---\n");
    int is_last[MAX_NODES] = {0};
    print_tree_node(g, start, parent, is_last, 0);
}

void calc_least_resistance(Graph *g) {
    int start, end;
    printf("Enter Source Asset ID: ");
    scanf("%d", &start);
    printf("Enter Target Asset ID: ");
    scanf("%d", &end);

    if (start < 0 || start >= MAX_NODES || !g->nodes[start].active ||
        end < 0 || end >= MAX_NODES || !g->nodes[end].active) {
        printf("Invalid asset IDs.\n");
        return;
    }

    int dist[MAX_NODES];
    int parent[MAX_NODES];
    int visited[MAX_NODES] = {0};

    for (int i = 0; i < MAX_NODES; i++) {
        dist[i] = INF;
        parent[i] = -1;
    }
    dist[start] = 0;

    for (int count = 0; count < MAX_NODES - 1; count++) {
        int min = INF, u = -1;
        for (int v = 0; v < MAX_NODES; v++) {
            if (g->nodes[v].active && !visited[v] && dist[v] <= min) {
                min = dist[v];
                u = v;
            }
        }
        
        if (u == -1) break;
        visited[u] = 1;

        for (int v = 0; v < MAX_NODES; v++) {
            if (g->nodes[v].active && !visited[v] && g->edges[u][v] > 0 &&
                dist[u] != INF && dist[u] + g->edges[u][v] < dist[v]) {
                dist[v] = dist[u] + g->edges[u][v];
                parent[v] = u;
            }
        }
    }

    if (dist[end] == INF) {
        printf("No path exists.\n");
        return;
    }

    printf("Least resistance path cost: %d\n", dist[end]);
    int path[MAX_NODES];
    int path_len = 0;
    int curr = end;
    while (curr != -1) {
        path[path_len++] = curr;
        if (curr == start) break;
        curr = parent[curr];
    }

    printf("Path: ");
    for (int i = path_len - 1; i >= 0; i--) {
        printf("%s", g->nodes[path[i]].name);
        if (i > 0) printf(" -> ");
    }
    printf("\n");
}

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    Graph g;
    init_graph(&g);
    int choice;

    while (1) {
        printf("\n=== NETBREACH CLI ===\n");
        printf("1. View Network Topology\n");
        printf("2. Simulate Blast Radius (BFS)\n");
        printf("3. Calculate Easiest Attack Path (Dijkstra)\n");
        printf("4. Add Network Asset\n");
        printf("5. Add Vulnerability/Connection\n");
        printf("6. Isolate Asset/Remove Node\n");
        printf("7. Exit\n");
        printf("Enter choice: ");
        
        if (scanf("%d", &choice) != 1) {
            while(getchar() != '\n'); 
            continue;
        }

        switch (choice) {
            case 1: print_network(&g); break;
            case 2: calc_blast_radius(&g); break;
            case 3: calc_least_resistance(&g); break;
            case 4: add_asset(&g); break;
            case 5: add_vulnerability(&g); break;
            case 6: remove_asset(&g); break;
            case 7: return 0;
            default: printf("Invalid choice.\n");
        }
    }
    return 0;
}
