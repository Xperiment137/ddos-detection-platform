const intervaloSegundos = 1000; 
const tablaBody = document.querySelector("#tablaResumen tbody");
const ctx = document.getElementById("graficoConteo").getContext("2d");
let grafico; 


const coloresPorClase = {
    "BENIGN": "#81C784",
    "DrDoS_DNS": "#E57373",
    "DrDoS_MSSQL": "#EF9A9A",
    "DrDoS_NetBIOS": "#CE93D8",
    "DrDoS_NTP": "#64B5F6",
    "DrDoS_SNMP": "#4DD0E1",
    "DrDoS_UDP": "#FFB74D",
    "Syn": "#FF8A65",
    "TFTP": "#A1887F"
};


async function actualizarResumenYGrafico() {
    const response = await fetch("/resumen_data/");
    const data = await response.json();

    console.log("Datos recibidos para el gráfico:", data);

    if (data.error) {
        console.error("❌ Error:", data.error);
        return;
    }

   
    const fechaExistente = Array.from(tablaBody.rows).some(row => row.cells[0].textContent === data.fecha);
    if (!fechaExistente) {
        const color = coloresPorClase[data.valor_mas_frecuente] || "#E0E0E0";
        const fila = document.createElement("tr");
        fila.innerHTML = `
            <td>${data.fecha}</td>
            <td style="background-color: ${color}; font-weight: bold;">${data.valor_mas_frecuente}</td>
            <td>${(data.confianza_media).toFixed(4)}</td>
        `;
        tablaBody.appendChild(fila);
    }

   
    const conteo = data.conteo_por_clase || {};
    const etiquetas = Object.keys(conteo);
    const valores = Object.values(conteo);
    const colores = etiquetas.map(etiqueta => coloresPorClase[etiqueta] || "#E0E0E0");

    if (grafico) {
        grafico.data.labels = etiquetas;
        grafico.data.datasets[0].data = valores;
        grafico.data.datasets[0].backgroundColor = colores;
        grafico.update();
    } else {
        grafico = new Chart(ctx, {
            type: "bar",
            data: {
                labels: etiquetas,
                datasets: [{
                    label: "", // sin texto
                    data: valores,
                    backgroundColor: colores,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false,
                        labels: {
                            generateLabels: () => [] 
                        }
                    },
                    tooltip: {
                        enabled: true
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
}


setInterval(actualizarResumenYGrafico, intervaloSegundos);
