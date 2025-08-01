#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void mstatus_mod(uint32_t *mstatus_ptr)
{
    uint32_t mstatus = *mstatus_ptr;

    uint32_t mie = (mstatus >> 3) & 1;
    mstatus &= ~(1 << 7);
    mstatus |= (mie << 7);

    mstatus &= ~(1 << 3);

    mstatus &= ~(3 << 11);
    mstatus |= (3 << 11);

    *mstatus_ptr = mstatus;
}

int main(int argc, char *argv[])
{
    printf("--------------------POXIM-V--------------------\n");
    // abertura dos arquivos de entrada e saída
    // FILE *input = fopen(argv[1], "r");
    // FILE *output = fopen(argv[2], "w");

    // FILE *terminal_in = fopen(argv[3], "r");
    // FILE *terminal_out = fopen(argv[4], "w");

    FILE *input = fopen("input.hex", "r");
    FILE *output = fopen("output.out", "w");

    FILE *terminal_in = fopen("qemu.terminal.in", "r");
    FILE *terminal_out = fopen("qemu.terminal.out", "w");

    printf("Entrada e saída lidos com sucesso!\n");

    // endereço inicial da memória
    const uint32_t endereco_inicial = 0x80000000;

    // array dos registradores e seus nomes
    uint32_t reg[32] = {0};
    const char *reg_nomes[32] = {
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
        "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
        "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
        "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};

    // array de CSRs
    uint32_t csr[7] = {0};
    const char *csr_nomes[7] = {"mstatus", "mie", "mtvec", "mepc", "mcause", "mtval", "mip"};

    // array para região UART
    uint32_t uart[6] = {0};
    int atual = 0;
    int proximo = 0;
    if (terminal_in != NULL)
    {
        atual = fgetc(terminal_in);
        proximo = fgetc(terminal_in);
        uart[5] = 0x00000061;
    }

    // Simulação do clint
    uint32_t clint[3] = {0};
    uint64_t mtime;

    // Simulação do plic
    uint32_t plic_priority = 0;
    uint32_t plic_pending = 0;
    uint32_t plic_enable = 0;
    uint32_t plic_threshold = 0;
    uint32_t plic_claim_complete = 0;

    // criação do pc inicializando em endereco_inicial
    uint32_t pc = endereco_inicial;

    // criação de array para memória
    uint8_t *mem = (uint8_t *)(malloc(32 * 1024));
    if (mem == NULL)
    {
        printf("Erro ao alocar memória!\n");
        return 1;
    }

    // ENTRADA
    // lê os bytes e armazena na memória
    uint32_t endereco_atual = endereco_inicial;
    char linha[76];

    while (fgets(linha, sizeof(linha), input))
    {
        if (linha[0] == '@')
        {
            endereco_atual = (uint32_t)strtol(linha + 1, NULL, 16);
        }
        else
        {
            unsigned int byte;
            int index = 0;
            while (sscanf(linha + index, "%2x", &byte) == 1)
            {
                mem[endereco_atual - endereco_inicial] = (uint8_t)byte;
                endereco_atual++;
                index += 3;
                if (linha[index] == '\0' || linha[index] == '\n')
                    break;
            }
        }
    }

    printf("Memória alocada com sucesso!\n");

    uint8_t run = 1;

    // csr[2] = 0x80000094;

    while (run)
    {
        if (pc < endereco_inicial || pc + 3 >= endereco_inicial + 32 * 1024)
        {
            // instruction fault
            csr[4] = 1;

            csr[3] = pc;

            csr[5] = pc;

            mstatus_mod(&csr[0]);

            fprintf(output, ">exception:instruction_fault    cause=0x%08x,epc=0x%08x,tval=0x%08x\n",
                    csr[4], csr[3], csr[5]);

            pc = csr[2];

            continue;
        }

        // Leitura da instrução na memória
        // 'instruction' contém os 4 bytes no endereço 'pc'
        uint32_t instruction = ((uint32_t *)mem)[(pc - endereco_inicial) >> 2];

        // Extração dos campos da instrução

        // Opcode (últimos 7 bits)
        uint8_t opcode = instruction & 0b1111111;

        // Campo rd (bits 7 a 11)
        uint8_t rd = (instruction >> 7) & 0b11111;

        // Campo funct3 (bits 12 a 14)
        uint8_t funct3 = (instruction >> 12) & 0b111;

        // Campo rs1 (bits 15 a 19)
        uint8_t rs1 = (instruction >> 15) & 0b11111;

        // Campo rs2 (bits 20 a 24)
        uint8_t rs2 = (instruction >> 20) & 0b11111;

        // Campo funct7 (bits 25 a 31)
        uint8_t funct7 = instruction >> 25;

        // Imediato I-type com sinal (12 bits)
        int32_t imm_i = ((int32_t)instruction) >> 20;

        // Imediato S-type (12 bits)
        // instruction[31:25] (7 bits) + instruction[11:7] (5 bits)
        int32_t imm_s = ((instruction >> 25) << 5) | ((instruction >> 7) & 0x1F);
        if (imm_s & 0x800)
        {
            imm_s |= 0xFFFFF000; // extensão de sinal
        }

        // Imediato B-type (branch) (13 bits, incluindo sinal)
        int32_t imm_b =
            ((instruction >> 31) & 0x1) << 12 |
            ((instruction >> 7) & 0x1) << 11 |
            ((instruction >> 25) & 0x3F) << 5 |
            ((instruction >> 8) & 0xF) << 1;
        if (imm_b & 0x1000)
        {
            imm_b |= 0xFFFFE000; // extensão de sinal
        }

        // Imediato J-type (jump) (21 bits, incluindo sinal)
        int32_t imm_j = 0;
        imm_j |= ((instruction >> 31) & 0x1) << 20;
        imm_j |= ((instruction >> 21) & 0x3FF) << 1;
        imm_j |= ((instruction >> 20) & 0x1) << 11;
        imm_j |= ((instruction >> 12) & 0xFF) << 12;
        if (imm_j & (1 << 20))
        {
            imm_j |= 0xFFF00000; // extensão de sinal
        }

        /*
        // Exemplo de imediato U-type (sem sinal) - comentado
        // uint32_t imm_u = (instruction >> 20) & 0xFFF;
        */

        switch (opcode)
        {
        case 0b0110011:
            // instruções R-type
            // operação add
            if (funct3 == 0b000 && funct7 == 0b0000000)
            {
                uint32_t valor = reg[rs1] + reg[rs2];

                fprintf(output, "0x%08x:add    %s,%s,%s     %s=0x%08x+0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2], reg_nomes[rd], reg[rs1], reg[rs2], valor);

                // registrador zero (x0) nunca é modificado
                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação sub
            else if (funct3 == 0b000 && funct7 == 0b0100000)
            {
                uint32_t valor = reg[rs1] - reg[rs2];

                fprintf(output, "0x%08x:sub    %s,%s,%s     %s=0x%08x-0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação sll
            else if (funct3 == 0b001 && funct7 == 0b0000000)
            {
                uint32_t valor = reg[rs1] << (reg[rs2] & 0x1F);

                fprintf(output, "0x%08x:sll    %s,%s,%s     %s=0x%08x<<%u=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2] & 0x1F, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação slt
            else if (funct3 == 0b010 && funct7 == 0b0000000)
            {
                uint32_t valor = ((int32_t)reg[rs1] < (int32_t)reg[rs2]) ? 1 : 0;

                fprintf(output, "0x%08x:slt    %s,%s,%s     %s=(0x%08x<0x%08x)=%u\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação sltu
            else if (funct3 == 0b011 && funct7 == 0b0000000)
            {
                uint32_t valor = (reg[rs1] < reg[rs2]) ? 1 : 0;

                fprintf(output, "0x%08x:sltu   %s,%s,%s     %s=(0x%08x<0x%08x)=%u\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação xor
            else if (funct3 == 0b100 && funct7 == 0b0000000)
            {
                uint32_t valor = reg[rs1] ^ reg[rs2];

                fprintf(output, "0x%08x:xor    %s,%s,%s     %s=0x%08x^0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação srl
            else if (funct3 == 0b101 && funct7 == 0b0000000)
            {
                uint32_t valor = reg[rs1] >> (reg[rs2] & 0x1F);

                fprintf(output, "0x%08x:srl    %s,%s,%s     %s=0x%08x>>%u=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2] & 0x1F, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação sra
            else if (funct3 == 0b101 && funct7 == 0b0100000)
            {
                uint32_t valor = (uint32_t)(((int32_t)reg[rs1]) >> (reg[rs2] & 0x1F));

                fprintf(output, "0x%08x:sra    %s,%s,%s     %s=0x%08x>>>%u=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2] & 0x1F, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação or
            else if (funct3 == 0b110 && funct7 == 0b0000000)
            {
                uint32_t valor = reg[rs1] | reg[rs2];

                fprintf(output, "0x%08x:or     %s,%s,%s     %s=0x%08x|0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação and
            else if (funct3 == 0b111 && funct7 == 0b0000000)
            {
                uint32_t valor = reg[rs1] & reg[rs2];

                fprintf(output, "0x%08x:and    %s,%s,%s     %s=0x%08x&0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação mul
            else if (funct3 == 0b000 && funct7 == 0b0000001)
            {
                uint32_t valor = reg[rs1] * reg[rs2];

                fprintf(output, "0x%08x:mul    %s,%s,%s     %s=0x%08x*0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação mulh
            else if (funct3 == 0b001 && funct7 == 0b0000001)
            {
                int64_t calculo = (int64_t)(int32_t)reg[rs1] * (int64_t)(int32_t)reg[rs2];
                uint32_t valor = (uint32_t)(calculo >> 32);

                fprintf(output, "0x%08x:mulh   %s,%s,%s     %s=0x%08x*0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação mulhsu
            else if (funct3 == 0b010 && funct7 == 0b0000001)
            {
                int64_t calculo = (int64_t)(int32_t)reg[rs1] * (uint64_t)reg[rs2];
                uint32_t valor = (uint32_t)(calculo >> 32);

                fprintf(output, "0x%08x:mulhsu %s,%s,%s     %s=0x%08x*0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação mulhu
            else if (funct3 == 0b011 && funct7 == 0b0000001)
            {
                uint64_t calculo = (uint64_t)reg[rs1] * (uint64_t)reg[rs2];
                uint32_t valor = (uint32_t)(calculo >> 32);

                fprintf(output, "0x%08x:mulhu  %s,%s,%s     %s=0x%08x*0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação div
            else if (funct3 == 0b100 && funct7 == 0b0000001)
            {
                int32_t valor;
                if (reg[rs2] == 0)
                {
                    valor = -1;
                }
                else
                {
                    valor = (int32_t)reg[rs1] / (int32_t)reg[rs2];
                }

                fprintf(output, "0x%08x:div    %s,%s,%s     %s=0x%08x/0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação divu
            else if (funct3 == 0b101 && funct7 == 0b0000001)
            {
                uint32_t valor;

                if (reg[rs2] == 0)
                {
                    valor = 0xFFFFFFFF;
                }
                else
                {
                    valor = reg[rs1] / reg[rs2];
                }

                fprintf(output, "0x%08x:divu   %s,%s,%s     %s=0x%08x/0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação rem
            else if (funct3 == 0b110 && funct7 == 0b0000001)
            {
                int32_t valor;

                if (reg[rs2] == 0)
                {
                    valor = reg[rs1];
                }
                else
                {
                    valor = (int32_t)reg[rs1] % (int32_t)reg[rs2];
                }

                fprintf(output, "0x%08x:rem    %s,%s,%s     %s=0x%08x%%0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação remu
            else if (funct3 == 0b111 && funct7 == 0b0000001)
            {
                uint32_t valor;

                if (reg[rs2] == 0)
                {
                    valor = reg[rs1];
                }
                else
                {
                    valor = reg[rs1] % reg[rs2];
                }

                fprintf(output, "0x%08x:remu    %s,%s,%s     %s=0x%08x%%0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], reg_nomes[rs2],
                        reg_nomes[rd], reg[rs1], reg[rs2], valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            break;
        case 0b0010011:
            // instruções I-type
            // operação addi
            if (funct3 == 0b000)
            {
                uint32_t valor = reg[rs1] + imm_i;

                fprintf(output, "0x%08x:addi   %s,%s,0x%03x     %s=0x%08x+0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], (uint16_t)(imm_i & 0xFFF), reg_nomes[rd], reg[rs1], imm_i, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação andi
            else if (funct3 == 0b111)
            {
                uint32_t valor = reg[rs1] & imm_i;

                fprintf(output, "0x%08x:andi   %s,%s,%03x   %s=0x%08x&0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], imm_i, reg_nomes[rd], reg[rs1], imm_i, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação ori
            else if (funct3 == 0b110)
            {
                uint32_t valor = reg[rs1] | imm_i;

                fprintf(output, "0x%08x:ori    %s,%s,%03x   %s=0x%08x|0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], imm_i, reg_nomes[rd], reg[rs1], imm_i, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação xori
            else if (funct3 == 0b100)
            {
                uint32_t valor = reg[rs1] ^ imm_i;

                fprintf(output, "0x%08x:xori   %s,%s,%03x   %s=0x%08x^0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], imm_i, reg_nomes[rd], reg[rs1], imm_i, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação sltiu
            else if (funct3 == 0b011)
            {
                uint32_t valor = (reg[rs1] < imm_i) ? 1 : 0;

                fprintf(output, "0x%08x:sltiu  %s,%s,0x%03x   %s=(0x%08x<0x%08x)=%u\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], imm_i, reg_nomes[rd], reg[rs1], imm_i, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação slti
            else if (funct3 == 0b010)
            {
                uint32_t valor = ((int32_t)reg[rs1] < imm_i) ? 1 : 0;

                fprintf(output, "0x%08x:slti   %s,%s,%03x   %s=(0x%08x<0x%08x)=%u\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], imm_i, reg_nomes[rd], reg[rs1], imm_i, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação slli
            else if (funct3 == 0b001 && funct7 == 0b0000000)
            {
                uint32_t valor = reg[rs1] << ((instruction >> 20) & 0x1F);

                fprintf(output, "0x%08x:slli   %s,%s,%u      %s=0x%08x<<%u=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], (instruction >> 20) & 0x1F,
                        reg_nomes[rd], reg[rs1], (instruction >> 20) & 0x1F, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação srli
            else if (funct3 == 0b101 && funct7 == 0b0000000)
            {
                uint32_t valor = reg[rs1] >> ((instruction >> 20) & 0x1F);

                fprintf(output, "0x%08x:srli   %s,%s,%u      %s=0x%08x>>%u=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], (instruction >> 20) & 0x1F,
                        reg_nomes[rd], reg[rs1], (instruction >> 20) & 0x1F, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            // operação srai
            else if (funct3 == 0b101 && funct7 == 0b0100000)
            {
                uint32_t valor = (uint32_t)(((int32_t)reg[rs1]) >> ((instruction >> 20) & 0x1F));

                fprintf(output, "0x%08x:srai   %s,%s,%u      %s=0x%08x>>%u=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], (instruction >> 20) & 0x1F,
                        reg_nomes[rd], reg[rs1], (instruction >> 20) & 0x1F, valor);

                if (rd != 0)
                    reg[rd] = valor;
            }
            break;
        case 0b0000011:
        {
            // instruções load
            uint32_t endereco = reg[rs1] + imm_i;

            int tamanho = 0;
            switch (funct3)
            {
            case 0b000: // lb
            case 0b100: // lbu
                tamanho = 1;
                break;
            case 0b001: // lh
            case 0b101: // lhu
                tamanho = 2;
                break;
            case 0b010: // lw
                tamanho = 4;
                break;
            default:
                tamanho = 0;
                break;
            }

            uint32_t valor = 0;

            // CLINT
            if (endereco >= 0x02000000 && endereco <= 0x0200BFFC)
            {

                if (endereco >= 0x02000000 && endereco <= 0x0200BFFC)
                {
                    if (endereco == 0x02000000)
                        valor = clint[0];
                    else if (endereco == 0x02004000)
                        valor = clint[1];
                    else if (endereco == 0x02004004)
                        valor = clint[2];
                    else if (endereco == 0x0200BFF8)
                        valor = (uint32_t)(mtime & 0xFFFFFFFF);
                    else if (endereco == 0x0200BFFC)
                        valor = (uint32_t)(mtime >> 32);
                }
                if (rd != 0)
                    reg[rd] = valor;

                fprintf(output, "0x%08x:lw     %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1],
                        reg_nomes[rd], endereco, reg[rd]);

                break;
            }

            // PLIC
            if (endereco == 0x0C000028)
            {
                valor = plic_priority;
                if (rd != 0)
                    reg[rd] = valor;
                fprintf(output, "0x%08x:lw     %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1], reg_nomes[rd], endereco, valor);
                break;
            }
            else if (endereco == 0x0C001000)
            {
                valor = plic_pending;
                if (rd != 0)
                    reg[rd] = valor;
                fprintf(output, "0x%08x:lw     %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1], reg_nomes[rd], endereco, valor);
                break;
            }
            else if (endereco == 0x0C002000)
            {
                valor = plic_enable;
                if (rd != 0)
                    reg[rd] = valor;
                fprintf(output, "0x%08x:lw     %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1], reg_nomes[rd], endereco, valor);
                break;
            }
            else if (endereco == 0x0C200004)
            {
                valor = plic_claim_complete;
                if (rd != 0)
                    reg[rd] = valor;
                fprintf(output, "0x%08x:lw     %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1], reg_nomes[rd], endereco, valor);
                break;
            }
            else if (endereco == 0x0C200000)
            {
                valor = plic_threshold;

                if (rd != 0)
                    reg[rd] = valor;

                fprintf(output, "0x%08x:lw     %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1],
                        reg_nomes[rd], endereco, valor);

                break;
            }

            // UART
            if (endereco == 0x10000000)
            {
                uart[0] = atual;

                if (rd != 0)
                    reg[rd] = (funct3 == 0b000) ? (int8_t)uart[0] : (uint8_t)uart[0];

                fprintf(output, "0x%08x:%s  %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc,
                        funct3 == 0b000 ? "lb " : "lbu",
                        reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1],
                        reg_nomes[rd], endereco, reg[rd]);

                if (proximo == EOF)
                {
                    uart[5] = 0x00000060;
                }
                else
                {
                    uart[5] = 0x00000061;
                }

                atual = proximo;
                proximo = fgetc(terminal_in);

                break;
            }
            else if (endereco == 0x10000005)
            {
                if (rd != 0)
                    reg[rd] = uart[5];

                fprintf(output, "0x%08x:%s  %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc,
                        funct3 == 0b000 ? "lb " : "lbu",
                        reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1],
                        reg_nomes[rd], endereco, reg[rd]);
                break;
            }

            else if (endereco == 0x10000002)
            {
                uint8_t valor = (plic_pending & (1 << 10)) ? 0x00 : 0x01;

                if (rd != 0)
                    reg[rd] = (funct3 == 0b000) ? (int8_t)valor : (uint8_t)valor;

                fprintf(output, "0x%08x:%s  %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc,
                        funct3 == 0b000 ? "lb    " : "lbu   ",
                        reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1],
                        reg_nomes[rd], endereco, reg[rd]);

                break;
            }

            if (tamanho == 0 || endereco < endereco_inicial || endereco + (tamanho - 1) >= endereco_inicial + 32 * 1024)
            {
                // Load fault
                csr[4] = 5;
                csr[3] = pc;
                csr[5] = endereco;

                mstatus_mod(&csr[0]);

                fprintf(output, ">exception:load_fault    cause=0x%08x,epc=0x%08x,tval=0x%08x\n",
                        csr[4], csr[3], csr[5]);

                pc = csr[2];
                continue;
            }

            uint32_t mem_index = endereco - endereco_inicial;

            // operação lb
            if (funct3 == 0b000)
            {
                int8_t valor = (int8_t)mem[mem_index];

                if (rd != 0)
                    reg[rd] = (int32_t)valor;

                fprintf(output, "0x%08x:lb     %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1], reg_nomes[rd], endereco, reg[rd]);
            }
            // operação lh
            else if (funct3 == 0b001)
            {
                int16_t valor = (int16_t)(mem[mem_index] | (mem[mem_index + 1] << 8));

                if (rd != 0)
                    reg[rd] = (int32_t)valor;

                fprintf(output, "0x%08x:lh     %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1], reg_nomes[rd], endereco, reg[rd]);
            }
            // operação lw
            else if (funct3 == 0b010)
            {
                uint32_t valor = mem[mem_index] | (mem[mem_index + 1] << 8) | (mem[mem_index + 2] << 16) | (mem[mem_index + 3] << 24);

                if (rd != 0)
                    reg[rd] = valor;

                fprintf(output, "0x%08x:lw     %s,%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rd], (int32_t)imm_i, reg_nomes[rs1], reg_nomes[rd], endereco, valor);
            }
            // operação lbu
            else if (funct3 == 0b100)
            {
                uint8_t valor = (uint8_t)mem[mem_index];

                if (rd != 0)
                    reg[rd] = (uint32_t)valor;

                fprintf(output, "0x%08x:lbu    %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1], reg_nomes[rd], endereco, reg[rd]);
            }
            // operação lhu
            else if (funct3 == 0b101)
            {
                uint16_t valor = mem[mem_index] | (mem[mem_index + 1] << 8);

                if (rd != 0)
                    reg[rd] = (uint32_t)valor;

                fprintf(output, "0x%08x:lhu    %s,0x%03x(%s)  %s=mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rd], imm_i & 0xFFF, reg_nomes[rs1], reg_nomes[rd], endereco, reg[rd]);
            }
            break;
        }
        case 0b0100011:
        {
            // instruções store
            uint32_t endereco = reg[rs1] + imm_s;

            uint32_t valor = reg[rs2];

            // CLINT
            if (endereco >= 0x02000000 && endereco <= 0x0200BFFC)
            {

                if (endereco == 0x02000000)
                    clint[0] = valor & 1;
                else if (endereco == 0x02004000)
                    clint[1] = valor;
                else if (endereco == 0x02004004)
                    clint[2] = valor;
                else if (endereco == 0x0200BFF8)
                    mtime = (mtime & 0xFFFFFFFF00000000ULL) | (uint64_t)valor;
                else if (endereco == 0x0200BFFC)
                    mtime = (mtime & 0x00000000FFFFFFFFULL) | ((uint64_t)valor << 32);

                fprintf(output, "0x%08x:sw     %s,0x%03x(%s) mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rs2], imm_s & 0xFFF, reg_nomes[rs1], endereco, valor);

                break;
            }

            // UART
            if (funct3 == 0b000 && endereco >= 0x10000000 && endereco <= 0x10000005)
            {
                uint32_t uart_endereco = endereco - 0x10000000;
                uart[uart_endereco] = valor;

                if (uart_endereco == 0)
                {
                    fputc(valor, terminal_out);
                    fflush(terminal_out);

                    if (!(plic_pending & (1 << 10)))
                        plic_pending |= (1 << 10);
                }

                fprintf(output, "0x%08x:sb     %s,0x%03x(%s) mem[0x%08x]=0x%02x\n",
                        pc, reg_nomes[rs2], imm_s & 0xFFF, reg_nomes[rs1],
                        endereco, valor);

                break;
            }

            // PLIC
            if (endereco == 0x0C000028)
            {
                plic_priority = valor;

                fprintf(output, "0x%08x:sw     %s,0x%03x(%s) mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rs2], imm_s & 0xFFF, reg_nomes[rs1], endereco, valor);

                break;
            }
            else if (endereco == 0x0C002000)
            {
                plic_enable = valor;

                fprintf(output, "0x%08x:sw     %s,0x%03x(%s) mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rs2], imm_s & 0xFFF, reg_nomes[rs1], endereco, valor);

                break;
            }
            else if (endereco == 0x0C200004)
            {
                if (valor == 10)
                {
                    plic_pending &= ~(1 << 10);
                }

                fprintf(output, "0x%08x:sw     %s,0x%03x(%s) mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rs2], imm_s & 0xFFF, reg_nomes[rs1], endereco, valor);

                break;
            }

            if (endereco < endereco_inicial || endereco + 3 >= endereco_inicial + 32 * 1024)
            {
                // Store fault
                csr[4] = 7;
                csr[3] = pc;
                csr[5] = endereco;

                mstatus_mod(&csr[0]);

                fprintf(output, ">exception:store_fault    cause=0x%08x,epc=0x%08x,tval=0x%08x\n",
                        csr[4], csr[3], csr[5]);

                pc = csr[2];
                continue;
            }
            // operação sb
            if (funct3 == 0b000)
            {
                uint8_t valor = (uint8_t)(reg[rs2] & 0xFF);
                mem[endereco - endereco_inicial] = valor;

                fprintf(output, "0x%08x:sb     %s,0x%03x(%s) mem[0x%08x]=0x%02x\n",
                        pc, reg_nomes[rs2], imm_s & 0xFFF, reg_nomes[rs1],
                        endereco, valor);
            }
            // operação sh
            else if (funct3 == 0b001)
            {
                uint16_t valor = (uint16_t)(reg[rs2] & 0xFFFF);
                mem[endereco - endereco_inicial] = valor & 0xFF;
                mem[endereco + 1 - endereco_inicial] = (valor >> 8) & 0xFF;

                fprintf(output, "0x%08x:sh     %s,0x%03x(%s) mem[0x%08x]=0x%04x\n",
                        pc, reg_nomes[rs2], imm_s & 0xFFF, reg_nomes[rs1],
                        endereco, valor);
            }
            // operação sw
            else if (funct3 == 0b010)
            {
                uint32_t valor = reg[rs2];
                mem[endereco - endereco_inicial] = valor & 0xFF;
                mem[endereco - endereco_inicial + 1] = (valor >> 8) & 0xFF;
                mem[endereco - endereco_inicial + 2] = (valor >> 16) & 0xFF;
                mem[endereco - endereco_inicial + 3] = (valor >> 24) & 0xFF;

                fprintf(output, "0x%08x:sw     %s,0x%03x(%s) mem[0x%08x]=0x%08x\n",
                        pc, reg_nomes[rs2], imm_s & 0xFFF, reg_nomes[rs1],
                        endereco, valor);
            }
            break;
        }
        case 0b1100011:
            // instruções branch
            // operação beq
            if (funct3 == 0b000)
            {
                fprintf(output, "0x%08x:beq    %s,%s,0x%03x  (0x%08x==0x%08x)=%u->pc=0x%08x\n",
                        pc, reg_nomes[rs1], reg_nomes[rs2], imm_b,
                        reg[rs1], reg[rs2], reg[rs1] == reg[rs2], pc + imm_b);

                if (reg[rs1] == reg[rs2])
                {
                    pc = pc + imm_b;
                    continue;
                }
            }
            // operação bne
            else if (funct3 == 0b001)
            {
                fprintf(output, "0x%08x:bne    %s,%s,0x%03x  (0x%08x!=0x%08x)=%u->pc=0x%08x\n",
                        pc, reg_nomes[rs1], reg_nomes[rs2], imm_b,
                        reg[rs1], reg[rs2], reg[rs1] != reg[rs2], pc + imm_b);

                if (reg[rs1] != reg[rs2])
                {
                    pc += imm_b;
                    continue;
                }
            }
            // operação blt
            else if (funct3 == 0b100)
            {
                fprintf(output, "0x%08x:blt    %s,%s,0x%03x         (0x%08x<0x%08x)=%u->pc=0x%08x\n",
                        pc, reg_nomes[rs1], reg_nomes[rs2], ((imm_b + 4) & 0xFFF),
                        reg[rs1], reg[rs2], reg[rs1] != reg[rs2], pc + imm_b);

                if ((int32_t)reg[rs1] < (int32_t)reg[rs2])
                {
                    pc += imm_b;
                    continue;
                }
            }
            // operação bge
            else if (funct3 == 0b101)
            {
                fprintf(output, "0x%08x:bge    %s,%s,0x%03x  (0x%08x>=0x%08x)=%u->pc=0x%08x\n",
                        pc, reg_nomes[rs1], reg_nomes[rs2], imm_b,
                        reg[rs1], reg[rs2], (int32_t)reg[rs1] >= (int32_t)reg[rs2], pc + imm_b);

                if ((int32_t)reg[rs1] >= (int32_t)reg[rs2])
                {
                    pc += imm_b;
                    continue;
                }
            }
            // operação bltu
            else if (funct3 == 0b110)
            {
                fprintf(output, "0x%08x:bltu   %s,%s,0x%03x  (0x%08x<0x%08x)=%u->pc=0x%08x\n",
                        pc, reg_nomes[rs1], reg_nomes[rs2], imm_b,
                        reg[rs1], reg[rs2], reg[rs1] < reg[rs2], pc + imm_b);

                if (reg[rs1] < reg[rs2])
                {
                    pc += imm_b;
                    continue;
                }
            }
            // operação bgeu
            else if (funct3 == 0b111)
            {
                fprintf(output, "0x%08x:bgeu   %s,%s,0x%03x  (0x%08x>=0x%08x)=%u->pc=0x%08x\n",
                        pc, reg_nomes[rs1], reg_nomes[rs2], imm_b,
                        reg[rs1], reg[rs2], reg[rs1] >= reg[rs2], pc + imm_b);

                if (reg[rs1] >= reg[rs2])
                {
                    pc += imm_b;
                    continue;
                }
            }
            break;
        case 0b1101111:
            // operação jal
            uint32_t next = pc + imm_j;
            uint32_t returnPC = pc + 4;

            fprintf(output, "0x%08x:jal    %s,0x%05x     pc=0x%08x,%s=0x%08x\n",
                    pc, reg_nomes[rd], (imm_j >> 1) & 0xFFFFF, next, reg_nomes[rd], returnPC);

            if (rd != 0)
                reg[rd] = returnPC;
            pc = next;
            continue;
        case 0b1100111:
            // operação jalr
            if (funct3 == 0b000)
            {
                uint32_t valor = (reg[rs1] + imm_i) & ~1;
                uint32_t returnPC = pc + 4;

                fprintf(output, "0x%08x:jalr   %s,%s,0x%03x     pc=0x%08x+0x%08x,%s=0x%08x\n",
                        pc, reg_nomes[rd], reg_nomes[rs1], imm_i & 0xFFF,
                        reg[rs1], imm_i, reg_nomes[rd], returnPC);

                if (rd != 0)
                    reg[rd] = returnPC;
                pc = valor;
                continue;
            }
            break;
        case 0b0110111:
        {
            // operação lui
            uint32_t imm_u = instruction & 0xFFFFF000;

            fprintf(output, "0x%08x:lui    %s,0x%05x     %s=0x%08x\n",
                    pc, reg_nomes[rd], imm_u >> 12, reg_nomes[rd], imm_u);

            if (rd != 0)
                reg[rd] = imm_u;
            pc += 4;
            continue;
        }
        case 0b0010111:
        {
            // operação auipc
            uint32_t imm_u = instruction & 0xFFFFF000;
            uint32_t result = pc + imm_u;

            fprintf(output, "0x%08x:auipc  %s,0x%05x     %s=0x%08x+0x%05x000=0x%08x\n",
                    pc, reg_nomes[rd], imm_u >> 12, reg_nomes[rd], pc, imm_u >> 12, result);

            if (rd != 0)
                reg[rd] = result;
            pc += 4;
            continue;
        }
        case 0b1110011:
            // campo CSR
            uint16_t csr_num = (instruction >> 20) & 0xFFF;
            int idx = (csr_num == 0x300)   ? 0
                      : (csr_num == 0x304) ? 1
                      : (csr_num == 0x305) ? 2
                      : (csr_num == 0x341) ? 3
                      : (csr_num == 0x342) ? 4
                      : (csr_num == 0x343) ? 5
                      : (csr_num == 0x344) ? 6
                                           : -1;

            // operação ebreak
            if (funct3 == 0b000 && imm_i == 1)
            {
                fprintf(output, "0x%08x:ebreak\n", pc);
                run = 0;
            }
            // operação ecall
            else if (funct3 == 0b000 && imm_i == 0)
            {
                fprintf(output, "0x%08x:ecall\n", pc);

                csr[4] = 11;
                csr[3] = pc;
                csr[5] = 0;

                mstatus_mod(&csr[0]);

                fprintf(output, ">exception:environment_call       cause=0x%08x,epc=0x%08x,tval=0x%08x\n",
                        csr[4], csr[3], csr[5]);

                pc = csr[2];

                continue;
            }
            // operação mret
            else if (funct3 == 0b000 && imm_i == 0x302)
            {
                fprintf(output, "0x%08x:mret            pc=0x%08x\n", pc, csr[3]);
                pc = csr[3];

                uint32_t mstatus = csr[0];

                uint32_t mpie = (mstatus >> 7) & 1;
                if (mpie)
                    mstatus |= (1 << 3);
                else
                    mstatus &= ~(1 << 3);

                mstatus |= (1 << 7);

                mstatus &= ~(3 << 11);

                csr[0] = mstatus;

                continue;
            }
            // operação CSRRW
            else if (funct3 == 0b001)
            {
                uint32_t value_csr = csr[idx];
                uint32_t value_rs1 = reg[rs1];

                csr[idx] = value_rs1;

                if (rd != 0)
                    reg[rd] = value_csr;

                fprintf(output,
                        "0x%08x:csrrw  %s,%s,%s     %s=%s=0x%08x,%s=%s=0x%08x\n",
                        pc, reg_nomes[rd], csr_nomes[idx], reg_nomes[rs1], reg_nomes[rd],
                        csr_nomes[idx], value_csr, csr_nomes[idx], reg_nomes[rs1], value_rs1);
            }
            // operação CSRRS
            else if (funct3 == 0b010)
            {
                uint32_t value_csr = csr[idx];
                uint32_t value_rs1 = reg[rs1];
                uint32_t result = value_csr | value_rs1;

                csr[idx] = result;

                if (rd != 0)
                    reg[rd] = value_csr;

                fprintf(output,
                        "0x%08x:csrrs  %s,%s,%s     %s=%s=0x%08x,%s|=%s=0x%08x|0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], csr_nomes[idx], reg_nomes[rs1],
                        reg_nomes[rd], csr_nomes[idx], value_csr, csr_nomes[idx], reg_nomes[rs1], value_csr, value_rs1, result);
            }
            // operação CSRRC
            else if (funct3 == 0b011)
            {
                uint32_t value_csr = csr[idx];
                uint32_t value_rs1 = reg[rs1];
                uint32_t result = value_csr & (~value_rs1);

                csr[idx] = result;

                if (rd != 0)
                    reg[rd] = value_csr;

                fprintf(output,
                        "0x%08x:csrrc  %s,%s,%s     %s=0x%08x,%s&~=0x%08x&~0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], csr_nomes[idx], reg_nomes[rs1],
                        reg_nomes[rd], value_csr, csr_nomes[idx], value_csr, value_rs1, result);
            }
            // operação CSRRWI
            else if (funct3 == 0b101)
            {
                uint32_t value_csr = csr[idx];
                uint32_t uimm = rs1;

                csr[idx] = uimm;

                if (rd != 0)
                    reg[rd] = value_csr;

                fprintf(output,
                        "0x%08x:csrrwi %s,%s,0x%x      %s=0x%08x,%s=u5=0x%08x\n",
                        pc, reg_nomes[rd], csr_nomes[idx], uimm,
                        reg_nomes[rd], value_csr, csr_nomes[idx], uimm);
            }
            // operação CSRRSI
            else if (funct3 == 0b110)
            {
                uint32_t value_csr = csr[idx];
                uint32_t uimm = rs1;

                uint32_t result = value_csr | uimm;
                csr[idx] = result;

                if (rd != 0)
                    reg[rd] = value_csr;

                fprintf(output,
                        "0x%08x:csrrsi %s,%s,0x%x      %s=0x%08x,%s|=u5=0x%08x|0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], csr_nomes[idx], uimm,
                        reg_nomes[rd], value_csr, csr_nomes[idx], value_csr, uimm, result);
            }
            // operação CSRRCI
            else if (funct3 == 0b111)
            {
                uint32_t value_csr = csr[idx];
                uint32_t uimm = rs1;

                uint32_t result = value_csr & (~uimm);
                csr[idx] = result;

                if (rd != 0)
                    reg[rd] = value_csr;

                fprintf(output,
                        "0x%08x:csrrci %s,%s,0x%x      %s=0x%08x,%s&~=u5=0x%08x&~0x%08x=0x%08x\n",
                        pc, reg_nomes[rd], csr_nomes[idx], uimm,
                        reg_nomes[rd], value_csr, csr_nomes[idx], value_csr, uimm, result);
            }
            break;
        default:
            // illegal instruction
            csr[4] = 2;
            csr[3] = pc;
            csr[5] = instruction;

            mstatus_mod(&csr[0]);

            fprintf(output, ">exception:illegal_instruction       cause=0x%08x,epc=0x%08x,tval=0x%08x\n",
                    csr[4], csr[3], csr[5]);

            pc = csr[2];
            continue;
        }

        // Simula o incremento do mtime
        mtime++;

        // Timer interrupt
        if ((csr[1] & (1 << 7)) &&
            (csr[0] & (1 << 3)) &&
            (mtime >= ((uint64_t)clint[2] << 32 | clint[1])))
        {
            csr[4] = 0x80000007;
            csr[3] = pc + 4;
            csr[5] = 0;
            mstatus_mod(&csr[0]);

            fprintf(output, ">interrupt:timer               cause=0x%08x,epc=0x%08x,tval=0x%08x\n",
                    csr[4], csr[3] + 4, csr[5]);

            uint32_t mtvec_val = csr[2];

            uint32_t base = mtvec_val & ~0x3;

            uint32_t cause = csr[4] & 0x7FFFFFFF;

            pc = base + 4 * cause;
            continue;
        }

        // Software interrupt
        if ((csr[1] & (1 << 3)) &&
            (csr[0] & (1 << 3)) &&
            (clint[0] & 1))
        {
            csr[4] = 0x80000003;
            csr[3] = pc + 4;
            csr[5] = 0;
            mstatus_mod(&csr[0]);

            fprintf(output, ">interrupt:software           cause=0x%08x,epc=0x%08x,tval=0x%08x\n",
                    csr[4], csr[3] + 4, csr[5]);

            uint32_t mtvec_val = csr[2];

            uint32_t base = mtvec_val & ~0x3;

            uint32_t cause = csr[4] & 0x7FFFFFFF;

            pc = base + 4 * cause;
            continue;
        }

        // external interrupt
        int ext_irq_ativa = (plic_pending & (1 << 10)) &&
                            (plic_enable & (1 << 10)) &&
                            (plic_priority > plic_threshold) &&
                            (csr[1] & (1 << 11)) &&
                            (csr[0] & (1 << 3));

        if (ext_irq_ativa)
        {
            csr[4] = 0x8000000B;
            csr[3] = pc + 4;
            csr[5] = 0;
            mstatus_mod(&csr[0]);

            uint32_t base = csr[2] & ~0x3;
            pc = base + 4 * 11;
            fprintf(output, ">interrupt:external         cause=0x%08x,epc=0x%08x,tval=0x%08x\n",
                    csr[4], csr[3] + 4, csr[5]);
            continue;
        }

        // incremento de pc para o próximo endereço
        pc += 4;
    }

    printf("Poxim-V executado com sucesso!\n");
    printf("-----------------------------------------------\n");

    // fechando arquivos de entrada e saída
    fclose(input);
    fclose(output);
    free(mem);

    return 0;
}