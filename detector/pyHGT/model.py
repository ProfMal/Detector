from .conv import *


class Classifier(nn.Module):

    def __init__(self, in_dim, hidden_dim, num_layers=2):
        super(Classifier, self).__init__()
        layers = []
        layers.append(nn.Linear(in_dim, hidden_dim))
        layers.append(nn.ReLU())
        for _ in range(num_layers - 1):
            layers.append(nn.Linear(hidden_dim, hidden_dim))
            layers.append(nn.ReLU())
        layers.append(nn.Linear(hidden_dim, 1))
        self.mlp = nn.Sequential(*layers)

    def forward(self, global_feature):
        out = self.mlp(global_feature)
        return out


class GNN(nn.Module):
    def __init__(self, in_dim, n_hid, num_types, num_relations, n_heads, n_layers, dropout=0.2, conv_name='hgt',
                 id2meta=None, prev_norm=False, last_norm=False):

        super(GNN, self).__init__()

        self.gcs = nn.ModuleList()
        self.num_types = num_types
        self.in_dim = in_dim
        self.n_hid = n_hid

        self.adapt_ws = nn.ModuleList()
        self.drop = nn.Dropout(dropout)
        for t in range(num_types):
            self.adapt_ws.append(nn.Linear(in_dim, n_hid))
        for l in range(n_layers - 1):
            self.gcs.append(GeneralConv(conv_name, n_hid, n_hid, num_types,
                                        num_relations, n_heads, dropout, id2meta, use_norm=prev_norm))
        self.gcs.append(GeneralConv(conv_name, n_hid, n_hid, num_types,
                                    num_relations, n_heads, dropout, id2meta, use_norm=last_norm))

    def forward(self, node_feature, node_type, edge_index, edge_type):
        res = torch.zeros(node_feature.size(0), self.n_hid).to(node_feature.device)
        for t_id in range(self.num_types):
            idx = (node_type == int(t_id))
            if idx.sum() == 0:
                continue
            res[idx] = torch.tanh(self.adapt_ws[t_id](node_feature[idx]))
        meta_xs = self.drop(res)
        del res
        for gc in self.gcs:
            meta_xs = gc(meta_xs, node_type, edge_index, edge_type)
        return meta_xs
