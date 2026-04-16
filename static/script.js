async function loadLogs() {
    const res = await fetch("/data");   // make sure this matches Flask route
    const data = await res.json();

    const table = document.querySelector("#logTable tbody");
    table.innerHTML = "";

    data.forEach(log => {

        let row = `<tr>
            <td>${log.timestamp}</td>
            <td>${log.src_ip}</td>
            <td>${log.attack_type}</td>
            <td class="${getClass(log.score)}">${log.score}</td>
        </tr>`;

        table.innerHTML += row;
    });
}

function getClass(score) {
    if (score > 80) return "high";
    if (score > 30) return "medium";
    return "low";
}

setInterval(loadLogs, 3000);