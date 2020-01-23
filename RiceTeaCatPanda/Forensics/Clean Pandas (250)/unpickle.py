import pickle

path_pickle_panda = "pandas.pkl"
path_pickle_soap = "soap.pkl"
path_out_panda = "pandas"
path_out_soap = "soap"

pp = open(path_pickle_panda, 'rb')
ps = open(path_pickle_soap, 'rb')

pp_data = pickle.load(pp)
ps_data = pickle.load(ps)

print(pp_data)
print(ps_data)
