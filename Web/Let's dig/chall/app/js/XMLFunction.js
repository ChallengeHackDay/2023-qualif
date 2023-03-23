function XMLFunction(){
    var xml = '' +
        '<?xml version="1.0" encoding="UTF-8"?>' +
        '<root>' +
        '<name>' + $('#name').val() + '</name>' +
        '<tel>' + $('#tel').val() + '</tel>' +
        '<email>' + $('#email').val() + '</email>' +
        '</root>';
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.onreadystatechange = function () {
        if(xmlhttp.readyState == 4){
            console.log(xmlhttp.readyState);
            console.log(xmlhttp.responseText);
            document.getElementById('infoMessage').innerHTML = xmlhttp.responseText;

        }
    }
    xmlhttp.open("POST","../process.php",true);
    xmlhttp.send(xml);
}