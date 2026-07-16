# Wordpress Via Zabbix Monitoring

make a .zip file of the folder "wp-zabbix-data" to upload as a plugin on your wordpress.
Just like a regular plugin and activate.

## Setup in Wordpress
Under Settings there will now be a menu "Zabbix Monitoring" and a page is associated with it.
Here there are options to select what you want Zabbix to monitor.
There is a "Zabbix Secret Token" field where you need to enter a secret that you want Zabbix to use.
The secret will be encrypted in Wordpress, to avoid that people can exploit clear text.

## Setup in Zabbix
In "Datacollection" > "Templates" you can import the yaml file located in the folder "zabbix_template" 
Basically create a new host and and add the template "Wordpress monitoring via plugin".
Under the menu Macro's you can set the "{$WORDPRESS_TOKEN}" and "{$WEBSITE}" values.
The "{$WORDPRESS_TOKEN}" is the "Zabbix Secret Token" you set in Wordpress.

And then the magic starts.

Please come with recommendations for what can be of interest for minitoring.

!!!! the log is just a proof of concept I am considering that combining 
with elasticsearch or opensearch the logs would be more valuable there.
