import pandas as pd
import plotly.express as px
import os
import streamlit as st

basePath = './Labels'
listDataset = []

for dir in os.listdir(basePath):
    if os.path.isfile(os.path.join(basePath, dir)) and dir.endswith(".csv"):
        listDataset.append(dir)


st.title('Visualisasi Bar Chart dan Line Chart 2D untuk Deteksi Serangan DDoS')

st.subheader('Dataset')

# Choose dataset
dataset = st.selectbox(
    'Select dataset',
    listDataset,
    placeholder='Select dataset'
)
st.write(f'Visualisasi data DDoS menggunakan dataset {dataset}')
df = pd.read_csv(os.path.join(basePath, dataset))
st.subheader('Jumlah Packet per Label')

axes = df['Label'].value_counts().reset_index()
plotDf = px.bar(axes, x='Label', y='count', color='Label')
st.plotly_chart(plotDf, theme='streamlit') 

st.subheader('Jumlah Serangan per Waktu')

label = df['Label'].unique().tolist()

if label.count('BENIGN') and len(label) == 1:
    st.warning('Tidak ada serangan yang terjadi')
else:
    label.remove('BENIGN')
label.append('All')

@st.cache_data(ttl=60)
def filter_plotDf(df: pd.DataFrame, labelFilter: list) -> pd.DataFrame:
    df = df[df['Label'].isin(labelFilter)]
    return df

labelFilter = st.multiselect(
    'Select Label',
    label,
    ['All']
)

if 'All' in labelFilter:
    labelFilter = label

try:
    axes = filter_plotDf(df, labelFilter).groupby(by=['Timestamp','Label']).size().reset_index(name='Count')
    plotDf = px.line(axes, x='Timestamp', y='Count', color='Label')
    st.plotly_chart(plotDf, theme='streamlit')
except:
    st.warning('Mohon pilih setidaknya satu label')

st.subheader('Sumber Serangan Berdasarkan IP')

@st.cache_data(ttl=60)
def filter_df(df: pd.DataFrame, labelFilter: list) -> pd.DataFrame:
    df = df[df['Label'] != 'BENIGN']
    df_ddos = df[['Source IP', 'Timestamp', 'Label']]
    df_ddos = df_ddos.groupby(by=['Timestamp', 'Source IP', 'Label']).agg({
        'Label': 'count',
    }).rename(columns={'Label': 'Jumlah'}).reset_index()
    df_ddos_filter = df_ddos[df_ddos['Label'].isin(labelFilter)]
    return df_ddos, df_ddos_filter

df_ddos, df_ddos_filter = filter_df(df, labelFilter)
st.dataframe(df_ddos_filter)

st.write('Rangkuman')

df_ddos_summary = df_ddos.groupby(by=['Source IP', 'Label']).agg({
    'Jumlah': 'sum',
}).rename(columns={'Jumlah': 'Total'}).sort_values(by='Total', ascending=False)
st.dataframe(df_ddos_summary)

def listToString(listItem : list) -> str:
    string = ', '.join(listItem) 
    return string

sourceIP = df_ddos_summary.index.get_level_values('Source IP').unique().tolist()
with st.expander("Lihat Penjelasan"):
    st.write(f'''
        IP yang melakukan serangan adalah {listToString(sourceIP)} dengan total serangan {df_ddos_summary["Total"].sum()}. Serangan ini menjadi beberapa jenis yaitu {listToString(df_ddos_summary.index.get_level_values("Label").unique().tolist())}. Serangan dilakukan pada rentang waktu {df_ddos["Timestamp"].min()} sampai {df_ddos["Timestamp"].max()}.''')

st.markdown("""
    ## PKDJK Kelompok 4 - B Informatika
    Anggota:
            
    - 2210511045 - Faiz Firstian Nugroho
    - 2210511054 - Dinda Cantika Putri
    - 2210511077 - Derajat Salim Wibowo
    - 2210511084 - Dzulfikri Adjmal
    - 2210511089 - Karenina Nurmelita Malik
    """)